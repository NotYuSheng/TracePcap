package com.tracepcap.governance;

/** Who may perform an action (#915). With login off everyone is an ANALYST. */
public enum PermissionLevel {
  /** Anyone who can use the app (signed in, when login is on). */
  ANALYST,
  /** Only callers with the Keycloak client role admin; with login off, SYSTEM_SETTINGS_EDITABLE. */
  ADMIN
}
