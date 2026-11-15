package com.tracepcap.governance;

import com.tracepcap.common.dto.PagedResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/audit-log")
@RequiredArgsConstructor
@Tag(name = "Audit Log", description = "Who changed which setting or rule, when, before and after")
public class AuditLogController {

  private final AuditLogService auditLogService;

  @GetMapping
  @Operation(
      summary = "List audited changes, newest first",
      description =
          "search matches the actor, action, target type or target id. targetTypes (repeatable)"
              + " limits the list to entries about those kinds of thing, e.g. detection-rule.")
  public PagedResponse<AuditLogDto> list(
      @RequestParam(defaultValue = "1") int page,
      @RequestParam(defaultValue = "50") int pageSize,
      @RequestParam(required = false) String search,
      @RequestParam(required = false) java.util.List<String> targetTypes) {
    return auditLogService.list(page, pageSize, search, targetTypes);
  }
}
