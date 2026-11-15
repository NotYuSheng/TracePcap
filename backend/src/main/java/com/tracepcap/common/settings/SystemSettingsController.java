package com.tracepcap.common.settings;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/system")
@RequiredArgsConstructor
@Tag(name = "System Settings", description = "Deploy-time settings and why each can or can't be changed")
public class SystemSettingsController {

  private final SystemSettingsService systemSettingsService;

  @GetMapping("/settings")
  @Operation(
      summary = "Every deploy-time setting with its effective value (read-only)",
      description =
          "Lists each environment-driven setting, grouped as infrastructure, memory-tied or"
              + " analysis policy, with its effective value and why it can't be changed in the app."
              + " Secrets are reported as set or not set; their values are never returned.")
  public List<SystemSettingDto> getSettings() {
    return systemSettingsService.list();
  }
}
