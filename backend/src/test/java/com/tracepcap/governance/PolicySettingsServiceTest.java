package com.tracepcap.governance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.tracepcap.common.exception.ForbiddenException;
import com.tracepcap.common.exception.ResourceNotFoundException;
import com.tracepcap.common.settings.EditablePolicy;
import com.tracepcap.common.settings.RuntimePolicy;
import com.tracepcap.common.settings.SystemSettingOverrideEntity;
import com.tracepcap.common.settings.SystemSettingOverrideRepository;
import com.tracepcap.config.security.CurrentActor;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Editable policy (#915 phase 5): permission per kind, validation, audit, reset. */
class PolicySettingsServiceTest {

  private final SystemSettingOverrideRepository repo = mock(SystemSettingOverrideRepository.class);
  private final RuntimePolicy policy = mock(RuntimePolicy.class);
  private final PermissionService permissions = mock(PermissionService.class);
  private final AuditLogService audit = mock(AuditLogService.class);
  private final CurrentActor actor = mock(CurrentActor.class);
  private final PolicySettingsService service =
      new PolicySettingsService(repo, policy, permissions, audit, actor);

  @Test
  void normaliseValidatesTypeAndRange() {
    assertThat(EditablePolicy.DNS_NXDOMAIN_SUSPICIOUS_RATIO.normalise(" 0.25 ")).isEqualTo("0.25");
    assertThat(EditablePolicy.FILE_RETENTION_HOURS.normalise("48")).isEqualTo("48");
    assertThatThrownBy(() -> EditablePolicy.DNS_NXDOMAIN_SUSPICIOUS_RATIO.normalise("1.5"))
        .hasMessageContaining("0 to 1");
    assertThatThrownBy(() -> EditablePolicy.FILE_RETENTION_HOURS.normalise("0"))
        .hasMessageContaining("from 1");
    assertThatThrownBy(() -> EditablePolicy.HTTP_MIN_REQUESTS.normalise("2.5"))
        .hasMessageContaining("whole number");
  }

  @Test
  void retentionNeedsTheRetentionPermission_thresholdsNeedAnalysisPolicy() {
    doThrow(new ForbiddenException("no")).when(permissions).require(PermissionAction.RETENTION);
    assertThatThrownBy(() -> service.set("FILE_RETENTION_HOURS", "24")).isInstanceOf(ForbiddenException.class);
    verify(repo, never()).save(any());

    when(policy.value(EditablePolicy.HTTP_MIN_REQUESTS)).thenReturn("20");
    when(policy.deployValue(EditablePolicy.HTTP_MIN_REQUESTS)).thenReturn("20");
    when(actor.username()).thenReturn("alice");
    service.set("HTTP_MIN_REQUESTS", "50");
    verify(permissions).require(PermissionAction.ANALYSIS_POLICY);
    verify(repo).save(any(SystemSettingOverrideEntity.class));
    verify(audit)
        .record(
            "system-setting.update",
            "system-setting",
            "HTTP_MIN_REQUESTS",
            Map.of("value", "20", "overridden", false),
            Map.of("value", "50", "overridden", true));
  }

  @Test
  void settingTheDeploymentsValueRemovesTheOverride() {
    when(policy.value(EditablePolicy.HTTP_MIN_REQUESTS)).thenReturn("50");
    when(policy.deployValue(EditablePolicy.HTTP_MIN_REQUESTS)).thenReturn("20");
    when(policy.isOverridden(EditablePolicy.HTTP_MIN_REQUESTS)).thenReturn(true);
    service.set("HTTP_MIN_REQUESTS", "20");
    verify(repo).deleteById("HTTP_MIN_REQUESTS");
    verify(repo, never()).save(any());
  }

  @Test
  void anInvalidValueIsRejectedBeforeAnythingIsWritten() {
    assertThatThrownBy(() -> service.set("DNS_NXDOMAIN_SUSPICIOUS_RATIO", "lots"))
        .isInstanceOf(IllegalArgumentException.class);
    verify(repo, never()).save(any());
    verifyNoInteractions(audit);
  }

  @Test
  void aDeployTimeSettingCantBeChanged() {
    assertThatThrownBy(() -> service.set("SURICATA_ENABLED", "false"))
        .isInstanceOf(ResourceNotFoundException.class);
    assertThatThrownBy(() -> service.reset("LLM_API_KEY")).isInstanceOf(ResourceNotFoundException.class);
  }

  @Test
  void resetWithoutAnOverrideIsANoOp() {
    service.reset("HTTP_MIN_REQUESTS");
    verify(repo, never()).deleteById(anyString());
    verify(audit, never()).record(anyString(), anyString(), anyString(), any(), any());
    verify(permissions).require(eq(PermissionAction.ANALYSIS_POLICY));
  }
}
