package com.tracepcap.governance;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/permissions")
@RequiredArgsConstructor
@Tag(name = "Permissions", description = "Who may change each setting or rule set (analysts or admins)")
public class PermissionController {

  private final PermissionService permissionService;

  @GetMapping
  @Operation(summary = "List configurable actions, the level each requires, and whether I may do it")
  public List<PermissionDto> list() {
    return permissionService.list();
  }

  @PutMapping("/{action}")
  @Operation(summary = "Set the level an action requires (admin only; audited)")
  public PermissionDto update(
      @PathVariable PermissionAction action, @Valid @RequestBody UpdatePermissionRequest request) {
    return permissionService.update(action, request.getLevel());
  }
}
