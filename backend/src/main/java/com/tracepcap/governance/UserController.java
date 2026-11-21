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
@RequestMapping("/users")
@RequiredArgsConstructor
@Tag(
    name = "Users",
    description = "Who has signed in and the roles their last sign-in carried. Read-only: people and role"
        + " assignments live in Keycloak")
public class UserController {

  private final PermissionService permissionService;
  private final UserDirectoryService userDirectory;

  @GetMapping
  @Operation(
      summary = "List everyone who has signed in, most recent first",
      description = "search matches the username or name. Empty with login off. Needs Read the audit log.")
  public PagedResponse<UserDto> list(
      @RequestParam(defaultValue = "1") int page,
      @RequestParam(defaultValue = "50") int pageSize,
      @RequestParam(required = false) String search) {
    permissionService.require(PermissionAction.READ_AUDIT_LOG);
    return userDirectory.list(page, pageSize, search);
  }
}
