package com.tracepcap.common.settings;

import com.tracepcap.common.settings.SystemSettingsCatalog.Entry;
import com.tracepcap.common.settings.SystemSettingsCatalog.Group;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;

/**
 * The effective value of every deploy-time setting, for the System settings view (#915). Most are
 * read-only; the {@link EditablePolicy} ones show their in-app override, if any, and whether the
 * caller may change them.
 */
@Service
@RequiredArgsConstructor
public class SystemSettingsService {

  private final Environment environment;
  private final RuntimePolicy runtimePolicy;
  private final PolicyEditGate editGate;

  public List<SystemSettingDto> list() {
    return SystemSettingsCatalog.ENTRIES.stream().map(this::toDto).toList();
  }

  /** One setting by its environment variable name. */
  public SystemSettingDto get(String key) {
    return SystemSettingsCatalog.ENTRIES.stream()
        .filter(e -> e.env().equals(key))
        .findFirst()
        .map(this::toDto)
        .orElseThrow(() -> new com.tracepcap.common.exception.ResourceNotFoundException("No setting " + key));
  }

  private SystemSettingDto toDto(Entry e) {
    var editable = EditablePolicy.of(e.env());
    if (editable.isPresent()) return toEditableDto(e, editable.get());
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

  private SystemSettingDto toEditableDto(Entry e, EditablePolicy p) {
    boolean canEdit = editGate.canEdit(p.kind());
    return SystemSettingDto.builder()
        .key(e.env())
        .label(e.label())
        .group(e.group().name())
        .value(runtimePolicy.value(p))
        .defaultValue(e.defaultValue())
        .secret(false)
        .set(true)
        .editable(canEdit)
        .inAppEditable(true)
        .deployValue(runtimePolicy.deployValue(p))
        .overridden(runtimePolicy.isOverridden(p))
        .takesEffect(p.takesEffect())
        .lockedReason(canEdit ? null : editGate.reason(p.kind()))
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
          "Analysis policy that is set when TracePcap is deployed, because changing it means"
              + " restarting a component. Set " + e.env() + " in the deployment's .env file and"
              + " restart.";
    };
  }
}
