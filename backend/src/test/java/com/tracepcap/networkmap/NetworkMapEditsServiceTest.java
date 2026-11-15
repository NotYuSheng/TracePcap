package com.tracepcap.networkmap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.tracepcap.common.exception.ForbiddenException;
import com.tracepcap.common.exception.ResourceNotFoundException;
import com.tracepcap.config.security.CurrentActor;
import com.tracepcap.file.repository.FileRepository;
import com.tracepcap.governance.AuditLogService;
import com.tracepcap.governance.PermissionAction;
import com.tracepcap.governance.PermissionService;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Network map edits: read, save (permission, audit), reset. */
class NetworkMapEditsServiceTest {

  private final UUID fileId = UUID.randomUUID();
  private final NetworkMapEditsRepository repo = mock(NetworkMapEditsRepository.class);
  private final FileRepository files = mock(FileRepository.class);
  private final PermissionService permissions = mock(PermissionService.class);
  private final AuditLogService audit = mock(AuditLogService.class);
  private final CurrentActor actor = mock(CurrentActor.class);
  private final NetworkMapEditsService service = new NetworkMapEditsService(repo, files, permissions, audit, actor);

  @BeforeEach
  void setUp() {
    when(files.existsById(fileId)).thenReturn(true);
    when(actor.username()).thenReturn("alice");
    when(repo.save(any())).thenAnswer(i -> i.getArgument(0));
  }

  @Test
  void neverEdited_readsEmpty() {
    when(repo.findById(fileId)).thenReturn(Optional.empty());
    var r = service.get(fileId);
    assertThat(r.edits().placements()).isEmpty();
    assertThat(r.updatedAt()).isNull();
  }

  @Test
  void save_needsThePermission_isAudited_andRecordsWho() {
    when(repo.findById(fileId)).thenReturn(Optional.empty());
    var edits = new NetworkMapEdits(Map.of("10.0.0.5", "type:other:10.0.0.0/24:Servers"), java.util.List.of(), Map.of(), Map.of());
    var r = service.save(fileId, edits);
    verify(permissions).require(PermissionAction.NETWORK_MAP);
    verify(audit).record(eq("network-map.edit"), eq("network-map"), eq(fileId.toString()), isNull(), eq(edits));
    assertThat(r.updatedBy()).isEqualTo("alice");
    assertThat(r.edits()).isEqualTo(edits);
  }

  @Test
  void save_withoutThePermission_writesNothing() {
    doThrow(new ForbiddenException("no")).when(permissions).require(PermissionAction.NETWORK_MAP);
    assertThatThrownBy(() -> service.save(fileId, NetworkMapEdits.empty())).isInstanceOf(ForbiddenException.class);
    verify(repo, never()).save(any());
  }

  @Test
  void reset_dropsTheEdits_andAuditsWhatWasThere() {
    var edits = new NetworkMapEdits(Map.of("a", "b"), null, null, null);
    var e = NetworkMapEditsEntity.builder().fileId(fileId).edits(edits).build();
    when(repo.findById(fileId)).thenReturn(Optional.of(e));
    service.reset(fileId);
    verify(repo).delete(e);
    verify(audit).record(eq("network-map.reset"), eq("network-map"), eq(fileId.toString()), eq(edits), isNull());
  }

  @Test
  void unknownCapture_is404() {
    UUID other = UUID.randomUUID();
    assertThatThrownBy(() -> service.get(other)).isInstanceOf(ResourceNotFoundException.class);
  }

  @Test
  void oldDocumentsWithoutTheNewParts_readAsEmptyParts() {
    var e = new NetworkMapEdits(Map.of("a", "b"), null, null, null);
    assertThat(e.groups()).isEmpty();
    assertThat(e.names()).isEmpty();
    assertThat(e.notes()).isEmpty();
  }

  @Test
  void aUserGroupIdMustBeOneOfTheAnalysts() {
    var validator = jakarta.validation.Validation.buildDefaultValidatorFactory().getValidator();
    var ok = new NetworkMapEdits.UserGroup("user:abc-123", "Payments", "network:vlan:10");
    var bad = new NetworkMapEdits.UserGroup("network:vlan:10", "Payments", "local");
    assertThat(validator.validate(ok)).isEmpty();
    assertThat(validator.validate(bad)).isNotEmpty();
  }
}
