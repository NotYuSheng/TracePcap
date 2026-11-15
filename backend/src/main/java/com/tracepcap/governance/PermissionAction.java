package com.tracepcap.governance;

/**
 * The actions whose required level is configurable (#915), with their defaults. Defaults favour
 * analysts (every change is audited anyway); retention is admin by default because it deletes
 * data. Changing these levels is not itself an entry here: it is always admin-only.
 */
public enum PermissionAction {
  DETECTION_RULES_GLOBAL(PermissionLevel.ANALYST, "Edit global detection rules",
      "Rules that flag conversations in every capture and network."),
  DETECTION_RULES_NETWORK(PermissionLevel.ANALYST, "Edit network detection rules",
      "Rules that belong to one network and flag conversations in its captures."),
  DETECTION_RULES_CAPTURE(PermissionLevel.ANALYST, "Edit capture detection rules",
      "Rules that apply to a single capture."),
  HOST_OCCUPANCY(PermissionLevel.ANALYST, "Split, merge or link devices",
      "Correct where one device ends and the next begins on an address in a capture, and whether"
          + " two MACs in a network are one device."),
  ADDRESS_DEFAULTS(PermissionLevel.ANALYST, "Edit address defaults",
      "The shared subnet labels, internal/external ranges and organisations every network starts from."),
  NETWORK_SETTINGS(PermissionLevel.ANALYST, "Edit network settings",
      "Per-network settings such as when a device counts as no longer seen."),
  NETWORK_MAP(PermissionLevel.ANALYST, "Edit network maps",
      "Move devices between groups on a capture's network map, and reset it to automatic."),
  ANALYSIS_POLICY(PermissionLevel.ANALYST, "Edit analysis policy",
      "Which analysis tools run and how, for new analyses."),
  RETENTION(PermissionLevel.ADMIN, "Edit retention",
      "How long captures and extracted data are kept before they are deleted.");

  private final PermissionLevel defaultLevel;
  private final String label;
  private final String description;

  PermissionAction(PermissionLevel defaultLevel, String label, String description) {
    this.defaultLevel = defaultLevel;
    this.label = label;
    this.description = description;
  }

  public PermissionLevel defaultLevel() {
    return defaultLevel;
  }

  public String label() {
    return label;
  }

  public String description() {
    return description;
  }
}
