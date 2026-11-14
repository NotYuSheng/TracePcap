package com.tracepcap.governance;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracepcap.config.security.CurrentActor;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.data.domain.Page;

/** The audit log list: free-text search, optionally limited to kinds of thing. */
class AuditLogServiceTest {

  private final AuditLogRepository repo = mock(AuditLogRepository.class);
  private final AuditLogService service = new AuditLogService(repo, mock(CurrentActor.class), new ObjectMapper());

  @Test
  void withoutTargetTypes_searchesEverything() {
    when(repo.search(any(), any())).thenReturn(Page.empty());
    service.list(1, 25, null, List.of());
    verify(repo).search(isNull(), any());
    verify(repo, never()).searchIn(any(), any(), any());
  }

  @Test
  void withTargetTypes_searchesOnlyThose_andStillMatchesText() {
    when(repo.searchIn(any(), any(), any())).thenReturn(Page.empty());
    service.list(1, 25, "Staff", List.of("network-map", "detection-rule"));
    verify(repo).searchIn(eq("%staff%"), eq(List.of("network-map", "detection-rule")), any());
  }
}
