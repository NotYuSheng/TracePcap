package com.tracepcap.governance;

/**
 * The four roles every install has. Their keys are the Keycloak client roles that give them; admin
 * always has every permission.
 */
public enum BuiltInRole {
  VIEWER("viewer"),
  ANALYST("analyst"),
  LEAD("lead"),
  ADMIN("admin");

  private final String key;

  BuiltInRole(String key) {
    this.key = key;
  }

  public String key() {
    return key;
  }
}
