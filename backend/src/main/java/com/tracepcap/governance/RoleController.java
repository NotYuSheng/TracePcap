package com.tracepcap.governance;

import io.swagger.v3.oas.annotations.Operation;
import jakarta.validation.Valid;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
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

  @PostMapping
  @ResponseStatus(HttpStatus.CREATED)
  @Operation(
      summary = "Create a custom role (admin only; audited)",
      description = "Its key is the Keycloak client role that gives it, which your identity team creates and"
          + " assigns in Keycloak. copyFrom starts it with another role's permissions.")
  public RoleDto create(@Valid @RequestBody CreateRoleRequest request) {
    return permissionService.createRole(
        request.getKey(), request.getLabel(), request.getDescription(), request.getCopyFrom());
  }

  @PatchMapping("/{key}")
  @Operation(
      summary = "Change a role: what it may do, a custom role's name and description, or make it the"
          + " default (admin only; audited)")
  public RoleDto update(@PathVariable String key, @Valid @RequestBody UpdateRoleRequest request) {
    RoleDto out = null;
    if (request.getLabel() != null || request.getDescription() != null) {
      out = permissionService.setDetails(key, request.getLabel(), request.getDescription());
    }
    if (request.getPermissions() != null) out = permissionService.setPermissions(key, request.getPermissions());
    if (Boolean.TRUE.equals(request.getDefaultRole())) out = permissionService.setDefault(key);
    return out != null
        ? out
        : permissionService.listRoles().stream()
            .filter(r -> r.getKey().equals(key))
            .findFirst()
            .orElseThrow(() -> new com.tracepcap.common.exception.ResourceNotFoundException("Role", "key", key));
  }

  @DeleteMapping("/{key}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @Operation(summary = "Delete a custom role (admin only; audited). Built-in roles and the default role can't be")
  public void delete(@PathVariable String key) {
    permissionService.deleteRole(key);
  }
}
