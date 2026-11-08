package com.tracepcap.governance;

import com.tracepcap.common.settings.SystemSettingDto;
import com.tracepcap.common.settings.SystemSettingsService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/system/settings")
@RequiredArgsConstructor
@Tag(name = "Policy Settings", description = "Change editable analysis policy in the app (audited)")
public class PolicySettingsController {

  private final PolicySettingsService policySettingsService;
  private final SystemSettingsService systemSettingsService;

  /** The new value, as typed. */
  public record SetValueRequest(@NotBlank @Size(max = 64) String value) {}

  @PutMapping("/{key}")
  @Operation(
      summary = "Override an editable policy setting (retention, detection thresholds)",
      description =
          "Needs the RETENTION or ANALYSIS_POLICY permission. Setting the deployment's value"
              + " removes the override. Audited.")
  public SystemSettingDto set(@PathVariable String key, @Valid @RequestBody SetValueRequest body) {
    policySettingsService.set(key, body.value());
    return systemSettingsService.get(key);
  }

  @DeleteMapping("/{key}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @Operation(summary = "Remove an override, so the deployment's value applies again (audited)")
  public void reset(@PathVariable String key) {
    policySettingsService.reset(key);
  }
}
