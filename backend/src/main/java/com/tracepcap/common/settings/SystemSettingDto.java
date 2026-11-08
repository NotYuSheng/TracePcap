package com.tracepcap.common.settings;

import lombok.Builder;
import lombok.Value;

/** One deploy-time setting as the System settings view shows it (#915 phase 1). */
@Value
@Builder
public class SystemSettingDto {
  /** The environment variable that sets it. */
  String key;

  String label;
  /** INFRASTRUCTURE | MEMORY | POLICY: decides why it can't be changed here. */
  String group;
  /** The effective value; null for a secret or when unset with no default. */
  String value;

  String defaultValue;
  /** A secret: the value is never returned, only {@link #set}. */
  boolean secret;
  /** Whether a value is in effect (set, or defaulted). */
  boolean set;
  /**
   * Whether the caller can change it in the app. Only the {@link EditablePolicy} settings ever
   * are, and only with the permission for their kind (#915 phase 5).
   */
  boolean editable;
  /** Whether it is one of the settings that can be changed in the app at all. */
  boolean inAppEditable;
  /** For an in-app-editable setting: the value from the deployment, used when not overridden. */
  String deployValue;
  /** Whether an in-app override is in effect instead of the deployment's value. */
  boolean overridden;
  /** For an in-app-editable setting: when a change takes effect. */
  String takesEffect;
  /** Why it can't be changed here, in words an analyst can act on. Null when editable. */
  String lockedReason;

  String description;
}
