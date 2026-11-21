package com.tracepcap.governance;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/permissions")
@RequiredArgsConstructor
@Tag(name = "Permissions", description = "The permission catalogue, and which permissions I have")
public class PermissionController {

  private final PermissionService permissionService;

  @GetMapping
  @Operation(summary = "List every permission, grouped, and whether I have it")
  public List<PermissionDto> list() {
    return permissionService.list();
  }
}
