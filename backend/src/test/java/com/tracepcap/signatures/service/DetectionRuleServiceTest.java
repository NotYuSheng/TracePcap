package com.tracepcap.signatures.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.tracepcap.common.exception.FieldValidationException;
import com.tracepcap.common.exception.ForbiddenException;
import com.tracepcap.config.security.CurrentActor;
import com.tracepcap.governance.AuditLogService;
import com.tracepcap.governance.PermissionAction;
import com.tracepcap.governance.PermissionService;
import com.tracepcap.signatures.dto.DetectionRuleRequest;
import com.tracepcap.signatures.dto.DetectionRuleRequest.Match;
import com.tracepcap.signatures.dto.RuleImportRequest;
import com.tracepcap.signatures.entity.DetectionRuleEntity;
import com.tracepcap.signatures.repository.DetectionRuleRepository;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/** Detection rule writes (#925 phase 1): permission, validation, versions, audit, import. */
class DetectionRuleServiceTest {

  private final DetectionRuleRepository repo = mock(DetectionRuleRepository.class);
  private final PermissionService permissions = mock(PermissionService.class);
  private final AuditLogService audit = mock(AuditLogService.class);
  private final CurrentActor actor = mock(CurrentActor.class);
  private final RuleSyncService ruleSync = mock(RuleSyncService.class);
  private final DetectionRuleService service = new DetectionRuleService(repo, permissions, audit, actor, ruleSync, mock(com.tracepcap.file.repository.FileRepository.class), mock(com.tracepcap.monitor.repository.NetworkRepository.class), mock(CustomSignatureService.class), mock(org.springframework.jdbc.core.JdbcTemplate.class));

  private static DetectionRuleRequest req(String name, int port) {
    return DetectionRuleRequest.builder()
        .name(name)
        .severity("high")
        .match(Match.builder().dstPort(port).build())
        .build();
  }

  @Test
  void writesNeedTheGlobalRulesPermission() {
    doThrow(new ForbiddenException("no")).when(permissions).require(PermissionAction.DETECTION_RULES_GLOBAL);
    assertThatThrownBy(() -> service.create(req("a", 1))).isInstanceOf(ForbiddenException.class);
    assertThatThrownBy(() -> service.importYaml(new RuleImportRequest("signatures: []", RuleImportRequest.Mode.MERGE)))
        .isInstanceOf(ForbiddenException.class);
    verify(repo, never()).saveAndFlush(any());
    verify(repo, never()).save(any());
  }

  @Test
  void createIsVersionOneByTheCaller_andAudited() {
    when(actor.username()).thenReturn("alice");
    var dto = service.create(req("c2", 4444));
    assertThat(dto.getVersion()).isEqualTo(1);
    assertThat(dto.getCreatedBy()).isEqualTo("alice");
    assertThat(dto.isEnabled()).isTrue();
    verify(audit).record(eq("detection-rule.create"), eq("detection-rule"), anyString(), isNull(), any());
  }

  @Test
  void aDuplicateNameIsAFieldError() {
    when(repo.findAllByName("C2")).thenReturn(List.of(entity("c2", 1)));
    assertThatThrownBy(() -> service.create(req("C2", 4444)))
        .isInstanceOfSatisfying(FieldValidationException.class, e -> assertThat(e.getErrors()).containsKey("name"));
  }

  @Test
  void updateBumpsTheVersionOnlyWhenSomethingChanged() {
    DetectionRuleEntity e = entity("c2", 4444);
    when(repo.findById(e.getId())).thenReturn(Optional.of(e));
    when(actor.username()).thenReturn("bob");

    assertThat(service.update(e.getId(), req("c2", 4444)).getVersion()).isEqualTo(1);
    verify(repo, never()).saveAndFlush(any());
    verify(repo, never()).save(any());

    var changed = service.update(e.getId(), req("c2", 5555));
    assertThat(changed.getVersion()).isEqualTo(2);
    assertThat(changed.getUpdatedBy()).isEqualTo("bob");
    verify(audit).record(eq("detection-rule.update"), eq("detection-rule"), eq(e.getId().toString()), any(), any());
  }

  @Test
  void importIsAllOrNothing() {
    String file =
        "signatures:\n  - name: ok\n    match: {dstPort: 1}\n  - name: bad\n    payload_regex: [{pattern: '('}]\n";
    assertThatThrownBy(() -> service.importYaml(new RuleImportRequest(file, RuleImportRequest.Mode.MERGE)))
        .isInstanceOfSatisfying(
            FieldValidationException.class,
            e -> assertThat(e.getErrors()).containsKey("rules[1] (bad).payloadRegex[0].pattern"));
    verify(repo, never()).saveAndFlush(any());
    verify(repo, never()).save(any());
  }

  @Test
  void importMergesByName_andReplaceDeletesTheRest() {
    DetectionRuleEntity same = entity("same", 1);
    DetectionRuleEntity changed = entity("changed", 1);
    DetectionRuleEntity gone = entity("gone", 1);
    when(repo.findGlobalByName("same")).thenReturn(Optional.of(same));
    when(repo.findGlobalByName("changed")).thenReturn(Optional.of(changed));
    when(repo.findByScopeOrderByNameAsc(DetectionRuleEntity.Scope.GLOBAL)).thenReturn(List.of(same, changed, gone));
    String file =
        "signatures:\n"
            + "  - {name: same, severity: high, match: {dstPort: 1}}\n"
            + "  - {name: changed, severity: high, match: {dstPort: 2}}\n"
            + "  - {name: new, severity: low, match: {app: TOR}}\n"
            + "  - {name: NEW, severity: low, match: {app: TOR}}\n";

    var result = service.importYaml(new RuleImportRequest(file, RuleImportRequest.Mode.REPLACE));

    assertThat(result.getCreated()).isEqualTo(1);
    assertThat(result.getUpdated()).isEqualTo(1);
    assertThat(result.getUnchanged()).isEqualTo(1);
    assertThat(result.getDeleted()).isEqualTo(1);
    assertThat(result.getDuplicates()).containsExactly("NEW");
    assertThat(changed.getVersion()).isEqualTo(2);
    verify(repo).delete(gone);
    verify(audit, times(3)).record(anyString(), eq("detection-rule"), anyString(), any(), any());
  }

  private static DetectionRuleEntity entity(String name, int port) {
    DetectionRuleEntity e = new DetectionRuleEntity();
    e.setId(java.util.UUID.randomUUID());
    e.setScope(DetectionRuleEntity.Scope.GLOBAL);
    e.setName(name);
    e.setSeverity("high");
    e.setEnabled(true);
    e.setMatchCriteria(new java.util.LinkedHashMap<>(java.util.Map.of("dstPort", port)));
    e.setPayloadContains(List.of());
    e.setPayloadRegex(List.of());
    e.setVersion(1);
    e.setCreatedBy("x");
    e.setUpdatedBy("x");
    return e;
  }
}
