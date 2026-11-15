package com.tracepcap.signatures.service;

import com.tracepcap.config.security.CurrentActor;
import com.tracepcap.governance.AuditLogService;
import com.tracepcap.governance.PermissionAction;
import com.tracepcap.governance.PermissionService;
import com.tracepcap.signatures.dto.RuleReapplyJobDto;
import jakarta.annotation.PreDestroy;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Runs Re-apply in the background (#925 phase 2): one job at a time, one capture per transaction
 * (see {@link RuleSyncService#reapply}), with its progress in {@code rule_reapply_jobs}. Starting
 * one while another runs returns the running one. A job cut short by a restart is marked
 * INTERRUPTED; starting again picks up whatever is still out of date, since re-apply is
 * idempotent.
 */
@Slf4j
@Service
public class RuleReapplyJobService {

  private final JdbcTemplate jdbc;
  private final RuleSyncService sync;
  private final PermissionService permissionService;
  private final AuditLogService auditLog;
  private final CurrentActor currentActor;
  private final ExecutorService executor =
      Executors.newSingleThreadExecutor(
          r -> {
            Thread t = new Thread(r, "rule-reapply");
            t.setDaemon(true);
            return t;
          });

  public RuleReapplyJobService(
      JdbcTemplate jdbc,
      RuleSyncService sync,
      PermissionService permissionService,
      AuditLogService auditLog,
      CurrentActor currentActor) {
    this.jdbc = jdbc;
    this.sync = sync;
    this.permissionService = permissionService;
    this.auditLog = auditLog;
    this.currentActor = currentActor;
  }

  /** A started job, and whether it's one that was already running. */
  public record Started(RuleReapplyJobDto job, boolean alreadyRunning) {}

  /** Starts re-applying to one capture, or to every out-of-date one. Audited. */
  @Transactional
  public Started start(UUID fileId) {
    permissionService.require(PermissionAction.DETECTION_RULES_GLOBAL);
    Optional<RuleReapplyJobDto> running = running();
    if (running.isPresent()) return new Started(running.get(), true);

    List<UUID> targets = fileId != null ? List.of(fileId) : sync.staleFiles();
    UUID id = UUID.randomUUID();
    String actor = currentActor.username(); // the worker thread has no request to ask
    jdbc.update(
        "INSERT INTO rule_reapply_jobs (id, file_id, status, total, requested_by, created_at)"
            + " VALUES (?, ?, 'RUNNING', ?, ?, ?)",
        id, fileId, targets.size(), actor, Timestamp.valueOf(LocalDateTime.now()));
    Map<String, Object> after = new LinkedHashMap<>();
    after.put("captures", targets.size());
    if (fileId != null) after.put("fileId", fileId.toString());
    auditLog.record("detection-rules.reapply", "detection-rule", fileId != null ? fileId.toString() : null, null, after);

    // Only once the job row is committed, so the worker (and a poller) can see it.
    TransactionSynchronizationManager.registerSynchronization(
        new TransactionSynchronization() {
          @Override
          public void afterCommit() {
            executor.submit(() -> run(id, targets, actor));
          }
        });
    return new Started(get(id).orElseThrow(), false);
  }

  public Optional<RuleReapplyJobDto> get(UUID id) {
    return jdbc.query("SELECT * FROM rule_reapply_jobs WHERE id = ?", MAPPER, id).stream().findFirst();
  }

  /** The most recent jobs, newest first. */
  public List<RuleReapplyJobDto> recent(int limit) {
    return jdbc.query("SELECT * FROM rule_reapply_jobs ORDER BY created_at DESC LIMIT ?", MAPPER, limit);
  }

  private Optional<RuleReapplyJobDto> running() {
    return jdbc.query("SELECT * FROM rule_reapply_jobs WHERE status = 'RUNNING' ORDER BY created_at DESC LIMIT 1", MAPPER)
        .stream()
        .findFirst();
  }

  /** How many device-type changes a job lists in its result; the count is always exact. */
  static final int MAX_LISTED_CHANGES = 100;

  void run(UUID jobId, List<UUID> targets, String actor) {
    int done = 0, failed = 0, reclassified = 0, staleLabels = 0;
    List<Map<String, Object>> changes = new java.util.ArrayList<>();
    String lastError = null;
    for (UUID fileId : targets) {
      try {
        RuleSyncService.ReapplyOutcome outcome = sync.reapply(fileId, actor);
        done++;
        // Device types re-scored from the rules' votes (#925): listed in the job's result.
        reclassified += outcome.rescore().changes().size();
        staleLabels += outcome.rescore().staleLabels();
        for (var c : outcome.rescore().changes()) {
          if (changes.size() >= MAX_LISTED_CHANGES) break;
          Map<String, Object> row = new LinkedHashMap<>();
          row.put("fileId", c.fileId().toString());
          row.put("ip", c.ip());
          row.put("from", c.from());
          row.put("to", c.to());
          row.put("rules", c.rules());
          changes.add(row);
        }
      } catch (Exception e) {
        failed++;
        lastError = fileId + ": " + e.getMessage();
        log.warn("Re-apply failed for capture {}: {}", fileId, e.getMessage());
      }
      jdbc.update(
          "UPDATE rule_reapply_jobs SET done = ?, failed = ?, reclassified_count = ?, stale_labels_count = ?,"
              + " reclassified = ?::jsonb WHERE id = ?",
          done, failed, reclassified, staleLabels, json(changes), jobId);
    }
    String status = failed > 0 && done == 0 ? "FAILED" : "DONE";
    jdbc.update(
        "UPDATE rule_reapply_jobs SET status = ?, error = ?, finished_at = ? WHERE id = ?",
        status, lastError, Timestamp.valueOf(LocalDateTime.now()), jobId);
    log.info("Re-apply job {} {}: {} capture(s) done, {} failed", jobId, status.toLowerCase(), done, failed);
  }

  /** A job can't survive a restart: mark any left RUNNING as INTERRUPTED. */
  @EventListener(ApplicationReadyEvent.class)
  public void markInterrupted() {
    int n =
        jdbc.update(
            "UPDATE rule_reapply_jobs SET status = 'INTERRUPTED', finished_at = ? WHERE status = 'RUNNING'",
            Timestamp.valueOf(LocalDateTime.now()));
    if (n > 0) log.warn("{} re-apply job(s) were interrupted by a restart; start Re-apply again to finish", n);
  }

  @PreDestroy
  void shutdown() {
    executor.shutdownNow();
  }

  private static final com.fasterxml.jackson.databind.ObjectMapper JSON = new com.fasterxml.jackson.databind.ObjectMapper();

  private static String json(Object o) {
    try {
      return JSON.writeValueAsString(o);
    } catch (Exception e) {
      return "[]";
    }
  }

  @SuppressWarnings("unchecked")
  private static List<Map<String, Object>> parseChanges(String raw) {
    if (raw == null || raw.isBlank()) return List.of();
    try {
      return JSON.readValue(raw, List.class);
    } catch (Exception e) {
      return List.of();
    }
  }

  private static final RowMapper<RuleReapplyJobDto> MAPPER =
      (rs, i) ->
          RuleReapplyJobDto.builder()
              .id(rs.getObject("id", UUID.class))
              .fileId(rs.getObject("file_id", UUID.class))
              .status(rs.getString("status"))
              .total(rs.getInt("total"))
              .done(rs.getInt("done"))
              .failed(rs.getInt("failed"))
              .error(rs.getString("error"))
              .requestedBy(rs.getString("requested_by"))
              .reclassifiedCount(rs.getInt("reclassified_count"))
              .staleLabelsCount(rs.getInt("stale_labels_count"))
              .reclassified(parseChanges(rs.getString("reclassified")))
              .createdAt(rs.getTimestamp("created_at").toLocalDateTime())
              .finishedAt(rs.getTimestamp("finished_at") == null ? null : rs.getTimestamp("finished_at").toLocalDateTime())
              .build();
}
