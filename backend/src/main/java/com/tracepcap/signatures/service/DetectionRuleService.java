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
  private final com.tracepcap.file.repository.FileRepository fileRepository;

  @Transactional(readOnly = true)
  public List<DetectionRuleDto> listGlobal() {
    return repository.findByScopeOrderByNameAsc(Scope.GLOBAL).stream().map(DetectionRuleService::toDto).toList();
  }

  /** The rules that apply to one capture: the global ones and its own (#925 phase 3). */
  @Transactional(readOnly = true)
  public List<DetectionRuleDto> listForFile(UUID fileId) {
    List<DetectionRuleDto> out = new ArrayList<>(listGlobal());
    out.addAll(listCapture(fileId));
    return out;
  }

  /** One capture's own rules. */
  @Transactional(readOnly = true)
  public List<DetectionRuleDto> listCapture(UUID fileId) {
    return repository.findByScopeAndFileIdOrderByNameAsc(Scope.CAPTURE, fileId).stream()
        .map(DetectionRuleService::toDto)
        .toList();
  }

  @Transactional(readOnly = true)
  public DetectionRuleDto get(UUID id) {
    return toDto(find(id));
  }

  @Transactional
  public DetectionRuleDto create(DetectionRuleRequest request) {
    permissionService.require(PermissionAction.DETECTION_RULES_GLOBAL);
    validateOrThrow(request);
    requireUniqueName(request.getName(), null, Scope.GLOBAL, null, null);
    DetectionRuleEntity e = newEntity(request, null);
    repository.save(e);
    DetectionRuleDto dto = toDto(e);
    auditLog.record("detection-rule.create", AUDIT_TARGET, e.getId().toString(), null, auditView(dto));
    return dto;
  }

  /**
   * Creates a rule for one capture (#925 phase 3). It's checked against that capture at once, so
   * its matches show straight away. Needs DETECTION_RULES_CAPTURE; audited.
   */
  @Transactional
  public DetectionRuleDto createForCapture(UUID fileId, DetectionRuleRequest request) {
    permissionService.require(PermissionAction.DETECTION_RULES_CAPTURE);
    var file =
        fileRepository
            .findById(fileId)
            .orElseThrow(() -> new ResourceNotFoundException("Capture not found: " + fileId));
    if (file.getStatus() != com.tracepcap.file.entity.FileEntity.FileStatus.COMPLETED) {
      throw new IllegalArgumentException("Rules can be added once the capture's analysis has completed.");
    }
    validateOrThrow(request);
    requireUniqueName(request.getName(), null, Scope.CAPTURE, fileId, null);
    DetectionRuleEntity e = newEntity(request, null);
    e.setScope(Scope.CAPTURE);
    e.setFileId(fileId);
    repository.saveAndFlush(e);
    DetectionRuleDto dto = toDto(e);
    auditLog.record("detection-rule.create", AUDIT_TARGET, e.getId().toString(), null, auditView(dto));
    if (e.isEnabled()) ruleSync.checkNow(fileId, List.of(e));
    return dto;
  }

  /**
   * Copies a capture rule up to a global one (#925 phase 3): a linked copy, so the two may share a
   * name. The copy is checked against the source capture at once, so its labels don't drop if the
   * original is removed; other captures show as out of date until re-applied, as for any new rule.
   */
  @Transactional
  public DetectionRuleDto promote(UUID id, boolean keepOriginal) {
    DetectionRuleEntity source = find(id);
    if (source.getScope() != Scope.CAPTURE) {
      throw new IllegalArgumentException("Only a capture rule can be promoted to a global rule.");
    }
    permissionService.require(PermissionAction.DETECTION_RULES_GLOBAL);
    if (!keepOriginal) permissionService.require(PermissionAction.DETECTION_RULES_CAPTURE);
    requireUniqueName(source.getName(), null, Scope.GLOBAL, null, source.getId());

    DetectionRuleEntity copy = newEntity(toRequest(source), source.getDeviceType());
    copy.setPromotedFrom(source.getId());
    repository.saveAndFlush(copy);
    DetectionRuleDto dto = toDto(copy);
    Map<String, Object> after = auditView(dto);
    after.put("promotedFrom", source.getId().toString());
    after.put("keptOriginal", keepOriginal);
    auditLog.record("detection-rule.promote", AUDIT_TARGET, copy.getId().toString(), auditView(toDto(source)), after);

    UUID fileId = source.getFileId();
    if (copy.isEnabled()) ruleSync.checkNow(fileId, List.of(copy));
    if (!keepOriginal) {
      auditLog.record("detection-rule.delete", AUDIT_TARGET, source.getId().toString(), auditView(toDto(source)), null);
      repository.delete(source);
      repository.flush();
      ruleSync.refreshLabels(List.of(fileId));
    }
    return dto;
  }

  @Transactional
  public DetectionRuleDto update(UUID id, DetectionRuleRequest request) {
    DetectionRuleEntity e = find(id);
    permissionService.require(permissionFor(e.getScope()));
    validateOrThrow(request);
    requireUniqueName(request.getName(), id, e.getScope(), e.getFileId(), e.getPromotedFrom());
    DetectionRuleDto before = toDto(e);
    if (!apply(e, request)) return before;
    repository.saveAndFlush(e);
    DetectionRuleDto after = toDto(e);
    auditLog.record("detection-rule.update", AUDIT_TARGET, id.toString(), auditView(before), auditView(after));
    if (e.getScope() == Scope.CAPTURE) {
      // A capture rule is re-checked at once (#925): it's one capture, and it's what the analyst
      // is looking at. A disabled one just has its labels hidden.
      if (e.isEnabled()) ruleSync.checkNow(e.getFileId(), List.of(e));
      else ruleSync.refreshLabels(List.of(e.getFileId()));
    } else {
      refreshLabelsIfShown(before, after);
    }
    return after;
  }

  @Transactional
  public void delete(UUID id) {
    DetectionRuleEntity e = find(id);
    permissionService.require(permissionFor(e.getScope()));
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
      if (existing.isEmpty()) {
        // A new global rule mustn't take a name a capture rule already uses.
        requireUniqueName(p.rule().getName(), null, Scope.GLOBAL, null, null);
      }
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
        .filter(e -> e.getScope() != Scope.NETWORK) // network rules arrive with #925 phase 3b
        .orElseThrow(() -> new ResourceNotFoundException("Detection rule not found: " + id));
  }

  static PermissionAction permissionFor(Scope scope) {
    return switch (scope) {
      case GLOBAL -> PermissionAction.DETECTION_RULES_GLOBAL;
      case NETWORK -> PermissionAction.DETECTION_RULES_NETWORK;
      case CAPTURE -> PermissionAction.DETECTION_RULES_CAPTURE;
    };
  }

  private static void validateOrThrow(DetectionRuleRequest r) {
    Map<String, String> errors = RuleCodec.validate(r);
    if (!errors.isEmpty()) throw new FieldValidationException("The rule isn't valid", errors);
  }

  /**
   * A rule's name is what its matches are labelled with, and global and capture rules both label
   * a capture, so a name must be unique among the global rules and the capture's own rules
   * together. The one exception is a rule and its promoted copy ({@code linked}), which are meant
   * to label the same thing.
   */
  private void requireUniqueName(String name, UUID self, Scope scope, UUID fileId, UUID linked) {
    for (DetectionRuleEntity other : repository.findAllByName(name.trim())) {
      if (other.getId().equals(self)) continue;
      if (linked != null && (other.getId().equals(linked) || linked.equals(other.getPromotedFrom()))) continue;
      if (self != null && self.equals(other.getPromotedFrom())) continue;
      boolean clash =
          switch (scope) {
            case GLOBAL -> other.getScope() == Scope.GLOBAL || other.getScope() == Scope.CAPTURE;
            case CAPTURE ->
                other.getScope() == Scope.GLOBAL
                    || (other.getScope() == Scope.CAPTURE && Objects.equals(other.getFileId(), fileId));
            case NETWORK -> false;
          };
      if (clash) {
        String where = other.getScope() == Scope.GLOBAL ? "A global rule" : "A rule on a capture";
        throw new FieldValidationException(
            "Duplicate name", Map.of("name", where + " is already called \"" + other.getName() + "\"."));
      }
    }
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
        .fileId(e.getFileId())
        .promotedFrom(e.getPromotedFrom())
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
