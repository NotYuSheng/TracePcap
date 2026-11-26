package com.tracepcap.governance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import io.swagger.v3.oas.annotations.Operation;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerMapping;

class RequestAuditInterceptorTest {

  // Stand-in handlers, annotated the way real controllers are.
  static class Handlers {
    @Operation(summary = "Mark a capture as a favourite")
    public void favourite() {}

    @NotAudited("a preview")
    public void preview() {}

    @AuditedAccess
    @Operation(summary = "Download file")
    public void download() {}

    public void read() {}
  }

  private final AuditLogService audit = mock(AuditLogService.class);
  @SuppressWarnings("unchecked")
  private final org.springframework.beans.factory.ObjectProvider<AuditLogService> provider =
      mock(org.springframework.beans.factory.ObjectProvider.class);

  {
    org.mockito.Mockito.when(provider.getIfAvailable()).thenReturn(audit);
  }

  private final RequestAuditInterceptor interceptor = new RequestAuditInterceptor(provider);

  private void call(String method, String pattern, Map<String, String> vars, String handler, int status)
      throws Exception {
    MockHttpServletRequest req = new MockHttpServletRequest(method, "/x");
    req.setAttribute(HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE, "/api/v1" + pattern);
    req.setAttribute(HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE, vars);
    MockHttpServletResponse res = new MockHttpServletResponse();
    res.setStatus(status);
    interceptor.afterCompletion(
        req, res, new HandlerMethod(new Handlers(), Handlers.class.getMethod(handler)), null);
  }

  @Test
  void actionNames_followTheRoute() {
    assertThat(RequestAuditInterceptor.describe("PUT", "/files/{fileId}/favourite", Map.of("fileId", "f1"), false))
        .isEqualTo(new RequestAuditInterceptor.Entry("file.favourite.set", "file", "f1"));
    assertThat(RequestAuditInterceptor.describe("POST", "/monitor/networks/{networkId}/snapshots", Map.of("networkId", "n1"), false))
        .isEqualTo(new RequestAuditInterceptor.Entry("network.snapshots.create", "network", "n1"));
    assertThat(RequestAuditInterceptor.describe("DELETE", "/files/{fileId}", Map.of("fileId", "f1"), false).action())
        .isEqualTo("file.delete");
    assertThat(RequestAuditInterceptor.describe("PUT", "/node-roles", Map.of(), false).action()).isEqualTo("node-role.set");
    assertThat(RequestAuditInterceptor.describe("POST", "/stories/{storyId}/questions", Map.of("storyId", "s"), false).action())
        .isEqualTo("story.questions.create");
    assertThat(RequestAuditInterceptor.describe("GET", "/files/{fileId}/download", Map.of("fileId", "f1"), true).action())
        .isEqualTo("file.download.download");
    // Acted on a capture, whatever the route's first word: grouped with the capture.
    assertThat(RequestAuditInterceptor.describe("GET", "/conversations/{fileId}/export", Map.of("fileId", "f1"), true))
        .isEqualTo(new RequestAuditInterceptor.Entry("conversation.export.download", "file", "f1"));
  }

  @Test
  @SuppressWarnings("unchecked")
  void aSuccessfulWrite_isRecorded_withTheEndpointsSummary() throws Exception {
    call("PUT", "/files/{fileId}/favourite", Map.of("fileId", "f1"), "favourite", 204);
    ArgumentCaptor<Map<String, Object>> after = ArgumentCaptor.forClass(Map.class);
    verify(audit).recordRequest(eq("file.favourite.set"), eq("file"), eq("f1"), after.capture());
    assertThat(after.getValue())
        .containsEntry("summary", "Mark a capture as a favourite")
        .containsEntry("request", "PUT /files/{fileId}/favourite")
        .containsEntry("status", 204)
        .doesNotContainKey("denied");
  }

  @Test
  void aRefusal_isRecordedAsDenied() throws Exception {
    call("DELETE", "/files/{fileId}", Map.of("fileId", "f1"), "favourite", 403);
    verify(audit).recordRequest(eq("file.delete.denied"), eq("file"), eq("f1"), any());
  }

  @Test
  void failures_reads_andExemptions_areNotRecorded() throws Exception {
    call("PUT", "/files/{fileId}/favourite", Map.of("fileId", "f1"), "favourite", 500);
    call("PUT", "/files/{fileId}/favourite", Map.of("fileId", "f1"), "favourite", 404);
    call("GET", "/files", Map.of(), "read", 200);
    call("POST", "/detection-rules/previews", Map.of(), "preview", 200);
    verify(audit, never()).recordRequest(anyString(), anyString(), any(), any());
  }

  @Test
  void aDownload_isRecorded() throws Exception {
    call("GET", "/files/{fileId}/download", Map.of("fileId", "f1"), "download", 200);
    verify(audit).recordRequest(eq("file.download.download"), eq("file"), eq("f1"), any());
  }

  @Test
  void aRequestWithItsOwnEntry_isNotRecordedTwice() throws Exception {
    MockHttpServletRequest req = new MockHttpServletRequest("PUT", "/x");
    req.setAttribute(HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE, "/api/v1/system/settings/{key}");
    req.setAttribute(AuditContext.RECORDED, Boolean.TRUE);
    MockHttpServletResponse res = new MockHttpServletResponse();
    interceptor.afterCompletion(
        req, res, new HandlerMethod(new Handlers(), Handlers.class.getMethod("favourite")), null);
    verify(audit, never()).recordRequest(anyString(), anyString(), any(), any());
  }
}
