package com.tracepcap.common.settings;

import com.tracepcap.common.settings.SystemSettingsCatalog.Entry;
import com.tracepcap.common.settings.SystemSettingsCatalog.Group;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;

/**
 * The effective value of every deploy-time setting, for the read-only System settings view (#915
 * phase 1). Works the same with login on or off: it shows values, and changes nothing.
 */
@Service
@RequiredArgsConstructor
public class SystemSettingsService {

  private final Environment environment;

  public List<SystemSettingDto> list() {
    return SystemSettingsCatalog.ENTRIES.stream().map(this::toDto).toList();
  }

  private SystemSettingDto toDto(Entry e) {
    // The bound property gives the effective value, including derived and defaulted ones. Settings
    // only the container entrypoint reads (APP_MEMORY_MB) are looked up by variable name.
    String raw = e.property() != null ? environment.getProperty(e.property()) : environment.getProperty(e.env());
    String effective = raw != null && !raw.isBlank() ? raw : e.defaultValue();
    boolean set = effective != null && !effective.isBlank();
    return SystemSettingDto.builder()
        .key(e.env())
        .label(e.label())
        .group(e.group().name())
        .value(e.secret() ? null : effective)
        .defaultValue(e.secret() ? null : e.defaultValue())
        .secret(e.secret())
        .set(set)
        .editable(false)
        .lockedReason(reason(e))
        .description(e.description())
        .build();
  }

  /** Why a setting is greyed out. Phase 1 changes nothing, so every setting has a reason. */
  static String reason(Entry e) {
    if (e.secret()) {
      return "A secret, so its value is never shown in the app. It's set in the deployment's .env"
          + " file as " + e.env() + ", and changing it needs a restart.";
    }
    return switch (e.group()) {
      case INFRASTRUCTURE ->
          "Part of how this install is wired up (servers, login, storage, the LLM). Set "
              + e.env() + " in the deployment's .env file; changing it needs a restart.";
      case MEMORY ->
          "Tied to how much memory the backend has (APP_MEMORY_MB). A wrong value can crash the"
              + " backend, so it isn't editable in the app. Set " + e.env()
              + " in the deployment's .env file and restart.";
      case POLICY ->
          "Analysis policy. Changing it in the app is planned (#915); until then, set "
              + e.env() + " in the deployment's .env file and restart.";
    };
  }
}
