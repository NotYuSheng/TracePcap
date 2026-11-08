package com.tracepcap.preferences;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The caller's personal preferences, a singleton per caller (#915 phase 2). With login on that's the
 * account's; with login off everyone shares one set, and {@code shared} says so.
 */
@RestController
@RequestMapping("/preferences")
@RequiredArgsConstructor
@Tag(name = "Preferences", description = "Personal preferences (theme, node labels, table columns)")
public class PreferencesController {

  private final PreferencesService preferencesService;

  @GetMapping
  @Operation(summary = "Get my preferences (shared by everyone when login is off)")
  public PreferencesDto get() {
    return preferencesService.get();
  }

  @PutMapping
  @Operation(summary = "Replace my preferences (shared by everyone when login is off)")
  public PreferencesDto put(@Valid @RequestBody PreferencesDto preferences) {
    return preferencesService.put(preferences);
  }
}
