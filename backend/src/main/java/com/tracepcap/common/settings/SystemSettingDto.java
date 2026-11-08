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
  /** Whether it can be changed in the app. False for everything in phase 1. */
  boolean editable;
  /** Why it can't be changed here, in words an analyst can act on. Null when editable. */
  String lockedReason;

  String description;
}
