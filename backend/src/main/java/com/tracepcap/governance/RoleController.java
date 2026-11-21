package com.tracepcap.governance;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/roles")
@RequiredArgsConstructor
@Tag(
    name = "Roles",
    description = "What each role may do. Who has a role is set in Keycloak, by the client role of the same key")
public class RoleController {

  private final PermissionService permissionService;

  @GetMapping
  @Operation(summary = "List the roles and what each may do")
  public List<RoleDto> list() {
    return permissionService.listRoles();
  }

  @PatchMapping("/{key}")
  @Operation(summary = "Change what a role may do, or make it the default role (admin only; audited)")
  public RoleDto update(@PathVariable String key, @RequestBody UpdateRoleRequest request) {
    RoleDto out = null;
    if (request.getPermissions() != null) out = permissionService.setPermissions(key, request.getPermissions());
    if (Boolean.TRUE.equals(request.getDefaultRole())) out = permissionService.setDefault(key);
    return out != null
        ? out
        : permissionService.listRoles().stream()
            .filter(r -> r.getKey().equals(key))
            .findFirst()
            .orElseThrow(() -> new com.tracepcap.common.exception.ResourceNotFoundException("Role", "key", key));
  }
}
