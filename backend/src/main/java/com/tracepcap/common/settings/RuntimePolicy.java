package com.tracepcap.common.settings;

import java.util.Map;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;

/**
 * The effective value of an editable policy setting (#915 phase 5): the in-app override if there
 * is one, otherwise the deploy-time value (env, or its default).
 *
 * <p>Read this at the point of use, not into a field at startup, or an override never takes
 * effect. Overrides are cached briefly, so a hot path costs no query; a write through this
 * process clears the cache at once, and other processes see it within {@link #TTL_MILLIS}.
 */
@Service
@RequiredArgsConstructor
public class RuntimePolicy {

  static final long TTL_MILLIS = 30_000;

  private final SystemSettingOverrideRepository repository;
  private final Environment environment;

  private volatile Map<String, String> cache;
  private volatile long loadedAt;

  public int getInt(EditablePolicy p) {
    return Integer.parseInt(value(p));
  }

  public double getDouble(EditablePolicy p) {
    return Double.parseDouble(value(p));
  }

  /** The effective value as text. */
  public String value(EditablePolicy p) {
    String override = overrides().get(p.name());
    return override != null ? override : deployValue(p);
  }

  /** The value from the deployment (env or its default), ignoring any override. */
  public String deployValue(EditablePolicy p) {
    SystemSettingsCatalog.Entry e = entry(p);
    String raw = environment.getProperty(e.property());
    return raw != null && !raw.isBlank() ? raw.trim() : e.defaultValue();
  }

  public boolean isOverridden(EditablePolicy p) {
    return overrides().containsKey(p.name());
  }

  /** Drops the cache; call after writing an override. */
  public void invalidate() {
    cache = null;
  }

  private Map<String, String> overrides() {
    Map<String, String> c = cache;
    if (c == null || System.currentTimeMillis() - loadedAt > TTL_MILLIS) {
      c =
          repository.findAll().stream()
              .collect(
                  Collectors.toUnmodifiableMap(
                      SystemSettingOverrideEntity::getKey, SystemSettingOverrideEntity::getValue));
      cache = c;
      loadedAt = System.currentTimeMillis();
    }
    return c;
  }

  static SystemSettingsCatalog.Entry entry(EditablePolicy p) {
    return SystemSettingsCatalog.ENTRIES.stream()
        .filter(e -> e.env().equals(p.name()))
        .findFirst()
        .orElseThrow(() -> new IllegalStateException(p + " is not in SystemSettingsCatalog"));
  }
}
