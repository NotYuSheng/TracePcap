package com.tracepcap.governance;

import com.tracepcap.config.security.CurrentActor;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/me")
@RequiredArgsConstructor
@Tag(name = "Me", description = "The current caller: identity, admin status and permissions")
public class MeController {

  private final CurrentActor currentActor;
  private final PermissionService permissionService;
  private final UserDirectoryService userDirectory;

  @GetMapping
  @Operation(
      summary = "Who I am and what I may change",
      description = "With login on, also records that the caller signed in (Settings › Users).")
  public MeDto me() {
    // The app asks this when it loads: that's a sign-in, for Settings › Users.
    userDirectory.recordCaller();
    return MeDto.builder()
        .username(currentActor.username())
        .authEnabled(currentActor.authEnabled())
        .admin(currentActor.isAdmin())
        .canManagePermissions(permissionService.canManage())
        .roles(permissionService.callerRoles().stream().map(RoleEntity::getKey).toList())
        .permissions(permissionService.list())
        .build();
  }
}
