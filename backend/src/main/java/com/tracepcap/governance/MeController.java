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

  @GetMapping
  @Operation(summary = "Who I am and what I may change")
  public MeDto me() {
    return MeDto.builder()
        .username(currentActor.username())
        .authEnabled(currentActor.authEnabled())
        .admin(currentActor.isAdmin())
        .canManagePermissions(permissionService.canManage())
        .permissions(permissionService.list())
        .build();
  }
}
