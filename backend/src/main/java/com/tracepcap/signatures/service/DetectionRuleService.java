package com.tracepcap.signatures.service;

import com.tracepcap.common.exception.FieldValidationException;
import com.tracepcap.common.exception.ResourceNotFoundException;
import com.tracepcap.config.security.CurrentActor;
import com.tracepcap.governance.AuditLogService;
import com.tracepcap.governance.PermissionAction;
import com.tracepcap.governance.PermissionService;
import com.tracepcap.signatures.dto.DetectionRuleDto;
import com.tracepcap.signatures.dto.DetectionRuleRequest;
import com.tracepcap.signatures.dto.RuleImportRequest;
import com.tracepcap.signatures.dto.RuleImportResult;
import com.tracepcap.signatures.entity.DetectionRuleEntity;
import com.tracepcap.signatures.entity.DetectionRuleEntity.Scope;
import com.tracepcap.signatures.repository.DetectionRuleRepository;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Detection rules in the database (#925 phase 1): global scope, edited in the System console.
 * Every write needs the DETECTION_RULES_GLOBAL permission and is audited; every edit bumps the
 * rule's version.
 */
@Service
@RequiredArgsConstructor
public class DetectionRuleService {

  static final String AUDIT_TARGET = "detection-rule";
  static final String EXPORT_HEADER =
      "# TracePcap detection rules (export). Import this file from System > Detection rules.\n"
          + "# Rules live in the database; this file is a backup or a way to move rules between\n"
          + "# installs, not configuration. See docs/configuration/signature-rules.rst.\n";

  private final DetectionRuleRepository repository;
  private final PermissionService permissionService;
  private final AuditLogService auditLog;
  private final CurrentActor currentActor;
  private final RuleSyncService ruleSync;

  @Transactional(readOnly = true)
  public List<DetectionRuleDto> listGlobal() {
    return repository.findByScopeOrderByNameAsc(Scope.GLOBAL).stream().map(DetectionRuleService::toDto).toList();
  }

  @Transactional(readOnly = true)
  public DetectionRuleDto get(UUID id) {
    return toDto(find(id));
  }

  @Transactional
  public DetectionRuleDto create(DetectionRuleRequest request) {
    permissionService.require(PermissionAction.DETECTION_RULES_GLOBAL);
    validateOrThrow(request);
    requireUniqueName(request.getName(), null);
    DetectionRuleEntity e = newEntity(request, null);
    repository.save(e);
    DetectionRuleDto dto = toDto(e);
    auditLog.record("detection-rule.create", AUDIT_TARGET, e.getId().toString(), null, auditView(dto));
    return dto;
  }

  @Transactional
  public DetectionRuleDto update(UUID id, DetectionRuleRequest request) {
    permissionService.require(PermissionAction.DETECTION_RULES_GLOBAL);
    validateOrThrow(request);
    DetectionRuleEntity e = find(id);
    requireUniqueName(request.getName(), id);
    DetectionRuleDto before = toDto(e);
    if (!apply(e, request)) return before;
    repository.saveAndFlush(e);
    DetectionRuleDto after = toDto(e);
    auditLog.record("detection-rule.update", AUDIT_TARGET, id.toString(), auditView(before), auditView(after));
    refreshLabelsIfShown(before, after);
    return after;
  }

  @Transactional
  public void delete(UUID id) {
    permissionService.require(PermissionAction.DETECTION_RULES_GLOBAL);
    DetectionRuleEntity e = find(id);
    DetectionRuleDto before = toDto(e);
    List<UUID> labelled = ruleSync.filesMatchedBy(id);
    repository.delete(e);
    repository.flush(); // its matches go with it (ON DELETE CASCADE) before the labels are rebuilt
    auditLog.record("detection-rule.delete", AUDIT_TARGET, id.toString(), auditView(before), null);
    ruleSync.refreshLabels(labelled);
  }

  /** All global rules in the file format. Reading needs no permission, like the list. */
  @Transactional(readOnly = true)
  public String exportYaml() {
    List<Map<String, Object>> rules = new ArrayList<>();
    for (DetectionRuleEntity e : repository.findByScopeOrderByNameAsc(Scope.GLOBAL)) {
      rules.add(RuleCodec.toYamlMap(toRequest(e), e.getDeviceType()));
    }
    return RuleCodec.formatYaml(rules, EXPORT_HEADER);
  }

  /**
   * Imports a rules file. All or nothing: every rule is validated first, and one invalid rule
   * rejects the file, with the errors keyed by rule. Rules are matched to existing ones by name.
   */
  @Transactional
  public RuleImportResult importYaml(RuleImportRequest request) {
    permissionService.require(PermissionAction.DETECTION_RULES_GLOBAL);
    List<RuleCodec.ParsedRule> parsed = RuleCodec.parseYaml(request.getContent());

    Map<String, String> errors = new LinkedHashMap<>();
    Map<String, RuleCodec.ParsedRule> byName = new LinkedHashMap<>();
    List<String> duplicates = new ArrayList<>();
    for (int i = 0; i < parsed.size(); i++) {
      RuleCodec.ParsedRule p = parsed.get(i);
      String label = "rules[" + i + "]" + (p.rule().getName() != null ? " (" + p.rule().getName() + ")" : "");
      RuleCodec.validate(p.rule()).forEach((field, msg) -> errors.putIfAbsent(label + "." + field, msg));
      if (p.rule().getName() == null) continue;
      String key = p.rule().getName().trim().toLowerCase(Locale.ROOT);
      if (byName.containsKey(key)) duplicates.add(p.rule().getName());
      else byName.put(key, p);
    }
    if (!errors.isEmpty()) {
      throw new FieldValidationException(
          errors.size() + " problem(s) in the file; nothing was imported", errors);
    }

    int created = 0, updated = 0, unchanged = 0, deleted = 0;
    Set<UUID> seen = new HashSet<>();
    for (RuleCodec.ParsedRule p : byName.values()) {
      var existing = repository.findGlobalByName(p.rule().getName().trim());
      if (existing.isPresent()) {
        DetectionRuleEntity e = existing.get();
        seen.add(e.getId());
        DetectionRuleDto before = toDto(e);
        boolean changed = apply(e, p.rule());
        if (!Objects.equals(e.getDeviceType(), p.deviceType())) {
          e.setDeviceType(p.deviceType());
          if (!changed) bump(e);
          changed = true;
        }
        if (changed) {
          repository.saveAndFlush(e);
          DetectionRuleDto after = toDto(e);
          auditLog.record("detection-rule.update", AUDIT_TARGET, e.getId().toString(), auditView(before), auditView(after));
          refreshLabelsIfShown(before, after);
          updated++;
        } else {
          unchanged++;
        }
      } else {
        DetectionRuleEntity e = newEntity(p.rule(), p.deviceType());
        repository.save(e);
        seen.add(e.getId());
        auditLog.record("detection-rule.create", AUDIT_TARGET, e.getId().toString(), null, auditView(toDto(e)));
        created++;
      }
    }
    if (request.getMode() == RuleImportRequest.Mode.REPLACE) {
      for (DetectionRuleEntity e : repository.findByScopeOrderByNameAsc(Scope.GLOBAL)) {
        if (seen.contains(e.getId())) continue;
        auditLog.record("detection-rule.delete", AUDIT_TARGET, e.getId().toString(), auditView(toDto(e)), null);
        List<UUID> labelled = ruleSync.filesMatchedBy(e.getId());
        repository.delete(e);
        repository.flush();
        ruleSync.refreshLabels(labelled);
        deleted++;
      }
    }
    return RuleImportResult.builder()
        .created(created)
        .updated(updated)
        .unchanged(unchanged)
        .deleted(deleted)
        .duplicates(duplicates)
        .build();
  }

  // ── helpers ──────────────────────────────────────────────────────────────────

  /**
   * Switching a rule on or off, or renaming it, changes what its existing matches are labelled
   * with, so those captures' labels are rewritten now (#925 phase 2). A change to what the rule
   * matches doesn't touch them: they show as out of date until someone re-applies.
   */
  private void refreshLabelsIfShown(DetectionRuleDto before, DetectionRuleDto after) {
    if (before.isEnabled() != after.isEnabled() || !before.getName().equals(after.getName())) {
      ruleSync.refreshLabels(ruleSync.filesMatchedBy(after.getId()));
    }
  }

  private DetectionRuleEntity find(UUID id) {
    return repository
        .findById(id)
        .filter(e -> e.getScope() == Scope.GLOBAL)
        .orElseThrow(() -> new ResourceNotFoundException("Detection rule not found: " + id));
  }

  private static void validateOrThrow(DetectionRuleRequest r) {
    Map<String, String> errors = RuleCodec.validate(r);
    if (!errors.isEmpty()) throw new FieldValidationException("The rule isn't valid", errors);
  }

  private void requireUniqueName(String name, UUID self) {
    repository
        .findGlobalByName(name.trim())
        .filter(other -> !other.getId().equals(self))
        .ifPresent(
            other -> {
              throw new FieldValidationException(
                  "Duplicate name",
                  Map.of("name", "A global rule called \"" + other.getName() + "\" already exists."));
            });
  }

  private DetectionRuleEntity newEntity(DetectionRuleRequest r, String deviceType) {
    String who = currentActor.username();
    LocalDateTime now = LocalDateTime.now();
    DetectionRuleEntity e =
        DetectionRuleEntity.builder()
            .id(UUID.randomUUID())
            .scope(Scope.GLOBAL)
            .deviceType(deviceType)
            .version(1)
            .createdAt(now)
            .createdBy(who)
            .updatedAt(now)
            .updatedBy(who)
            .build();
    copy(e, r);
    return e;
  }

  /** Copies the request onto the rule and bumps the version, if anything changed. */
  private boolean apply(DetectionRuleEntity e, DetectionRuleRequest r) {
    DetectionRuleRequest before = toRequest(e);
    DetectionRuleRequest after = normalised(r);
    if (before.equals(after)) return false;
    copy(e, r);
    bump(e);
    return true;
  }

  private void bump(DetectionRuleEntity e) {
    e.setVersion(e.getVersion() + 1);
    e.setUpdatedAt(LocalDateTime.now());
    e.setUpdatedBy(currentActor.username());
  }

  private static void copy(DetectionRuleEntity e, DetectionRuleRequest r) {
    e.setName(r.getName().trim());
    e.setDescription(r.getDescription() == null || r.getDescription().isBlank() ? null : r.getDescription().trim());
    e.setSeverity(r.getSeverity());
    e.setEnabled(r.isEnabled());
    e.setMatchCriteria(RuleCodec.toMatchMap(r.getMatch()));
    e.setPayloadContains(RuleCodec.toPayloadContains(r.getPayloadContains()));
    e.setPayloadRegex(RuleCodec.toPayloadRegex(r.getPayloadRegex()));
    e.setMatchAll(r.isMatchAll());
  }

  /** The request as it would be stored, so "did anything change" compares like with like. */
  private static DetectionRuleRequest normalised(DetectionRuleRequest r) {
    DetectionRuleEntity tmp = new DetectionRuleEntity();
    copy(tmp, r);
    return toRequest(tmp);
  }

  static DetectionRuleRequest toRequest(DetectionRuleEntity e) {
    return DetectionRuleRequest.builder()
        .name(e.getName())
        .description(e.getDescription())
        .severity(e.getSeverity())
        .enabled(e.isEnabled())
        .match(RuleCodec.fromMatchMap(e.getMatchCriteria()))
        .payloadContains(RuleCodec.fromPayloadContains(e.getPayloadContains()))
        .payloadRegex(RuleCodec.fromPayloadRegex(e.getPayloadRegex()))
        .matchAll(e.isMatchAll())
        .build();
  }

  static DetectionRuleDto toDto(DetectionRuleEntity e) {
    DetectionRuleRequest r = toRequest(e);
    return DetectionRuleDto.builder()
        .id(e.getId())
        .scope(e.getScope().name())
        .name(r.getName())
        .description(r.getDescription())
        .severity(r.getSeverity())
        .enabled(r.isEnabled())
        .match(r.getMatch())
        .payloadContains(r.getPayloadContains())
        .payloadRegex(r.getPayloadRegex())
        .matchAll(r.isMatchAll())
        .deviceType(e.getDeviceType())
        .version(e.getVersion())
        .createdAt(e.getCreatedAt())
        .createdBy(e.getCreatedBy())
        .updatedAt(e.getUpdatedAt())
        .updatedBy(e.getUpdatedBy())
        .build();
  }

  /** What the audit log keeps of a rule: its content and version, in the file format. */
  private static Map<String, Object> auditView(DetectionRuleDto d) {
    Map<String, Object> v = new LinkedHashMap<>(RuleCodec.toYamlMap(
        DetectionRuleRequest.builder()
            .name(d.getName())
            .description(d.getDescription())
            .severity(d.getSeverity())
            .enabled(d.isEnabled())
            .match(d.getMatch())
            .payloadContains(d.getPayloadContains())
            .payloadRegex(d.getPayloadRegex())
            .matchAll(d.isMatchAll())
            .build(),
        d.getDeviceType()));
    v.put("version", d.getVersion());
    return v;
  }
}
