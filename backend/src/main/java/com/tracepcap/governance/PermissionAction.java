package com.tracepcap.governance;

/**
 * Everything a role can be allowed to do: the permission catalogue. Each role (see {@link
 * RoleEntity}) holds a set of these. Two are fixed: everyone may {@link #SEE_CAPTURES}, and only
 * the admin role may {@link #MANAGE_ROLES}.
 */
public enum PermissionAction {
  // Look
  SEE_CAPTURES(Group.LOOK, BuiltInRole.VIEWER, "See captures, networks and findings",
      "Every page, the map, the story and the conversations. Every role has it."),
  DOWNLOAD_REPORT(Group.LOOK, BuiltInRole.VIEWER, "Download a report",
      "The PDF briefing or full report of a capture."),
  READ_AUDIT_LOG(Group.LOOK, BuiltInRole.LEAD, "Read the audit log and who has signed in",
      "Who changed what across the install, and who has signed in with which roles."),

  // Investigate
  UPLOAD_CAPTURES(Group.INVESTIGATE, BuiltInRole.ANALYST, "Upload and analyse captures",
      "Upload, merge, and re-analyse with other options."),
  ASK_AI(Group.INVESTIGATE, BuiltInRole.ANALYST, "Ask the AI",
      "The story, the chat, insights, role and subnet suggestions, packet explanations."),
  EXPORT_PACKETS(Group.INVESTIGATE, BuiltInRole.ANALYST, "Export packets",
      "The capture itself, filtered PCAPs, CSVs and extracted files leave the app."),

  // Curate findings
  LABEL_HOSTS(Group.CURATE, BuiltInRole.ANALYST, "Label hosts and add notes",
      "Roles, names and notes on hosts and subnets."),
  OVERRIDE_ANSWERS(Group.CURATE, BuiltInRole.ANALYST, "Override an answer",
      "Victim, user, malware and C2: override the answer, add or change evidence."),
  HOST_OCCUPANCY(Group.CURATE, BuiltInRole.ANALYST, "Split, merge or link devices",
      "Correct where one device ends and the next begins on an address in a capture, and whether"
          + " two MACs in a network are one device."),
  NETWORK_MAP(Group.CURATE, BuiltInRole.ANALYST, "Edit network maps",
      "Move devices between groups on a capture's network map, and reset it to automatic."),

  // Detection rules
  DETECTION_RULES_CAPTURE(Group.RULES, BuiltInRole.ANALYST, "Edit capture detection rules",
      "Rules that apply to a single capture."),
  DETECTION_RULES_NETWORK(Group.RULES, BuiltInRole.ANALYST, "Edit network detection rules",
      "Rules that belong to one network and flag conversations in its captures."),
  DETECTION_RULES_GLOBAL(Group.RULES, BuiltInRole.LEAD, "Edit global detection rules",
      "Rules that flag conversations in every capture and network."),

  // Monitor
  NETWORK_CAPTURES(Group.MONITOR, BuiltInRole.ANALYST, "Add and remove captures in a network",
      "Snapshots, notes, outside events, baselines, and reviewing changes."),
  NETWORK_CREATE(Group.MONITOR, BuiltInRole.ANALYST, "Create a network",
      "A new monitored network."),
  NETWORK_SETTINGS(Group.MONITOR, BuiltInRole.LEAD, "Edit network settings",
      "A network's name, addresses and subnets, and when a device counts as no longer seen."),
  NETWORK_DELETE(Group.MONITOR, BuiltInRole.LEAD, "Delete a network",
      "The network, its snapshots and notes."),

  // Keep and delete data
  KEEP_CAPTURES(Group.DATA, BuiltInRole.ANALYST, "Keep a capture longer, or forever",
      "A capture's expiry and Keep forever."),
  DELETE_OWN_CAPTURES(Group.DATA, BuiltInRole.ANALYST, "Delete your own captures",
      "Captures you uploaded."),
  DELETE_ANY_CAPTURES(Group.DATA, BuiltInRole.LEAD, "Delete anyone's captures",
      "Any capture and its analysis, including ones uploaded before owners were recorded."),
  RETENTION(Group.DATA, BuiltInRole.ADMIN, "Edit retention",
      "How long captures and extracted data are kept before they are deleted."),

  // Run the install
  ADDRESS_DEFAULTS(Group.INSTALL, BuiltInRole.LEAD, "Edit address defaults",
      "The shared subnet labels, internal/external ranges and organisations every network starts from."),
  ANALYSIS_POLICY(Group.INSTALL, BuiltInRole.ADMIN, "Edit analysis policy",
      "Which analysis tools run and how, for new analyses."),
  LLM_CONNECTION(Group.INSTALL, BuiltInRole.ADMIN, "Edit the LLM connection",
      "Which LLM server, key and model Story and Insights use, and testing the connection. The"
          + " server receives captures' details."),
  CANCEL_OTHERS_AI_JOBS(Group.INSTALL, BuiltInRole.LEAD, "Cancel someone else's AI work",
      "Take another person's waiting job out of line."),
  MANAGE_ROLES(Group.INSTALL, BuiltInRole.ADMIN, "Change who may do what",
      "What each role may do, and the default role. Only the admin role has it.");

  /** The catalogue's sections, in the order Settings › Permissions lists them. */
  public enum Group {
    LOOK("Look"),
    INVESTIGATE("Investigate"),
    CURATE("Curate findings"),
    RULES("Detection rules"),
    MONITOR("Monitor"),
    DATA("Keep and delete data"),
    INSTALL("Run the install");

    private final String label;

    Group(String label) {
      this.label = label;
    }

    public String label() {
      return label;
    }
  }

  private final Group group;
  private final BuiltInRole lowest;
  private final String label;
  private final String description;

  PermissionAction(Group group, BuiltInRole lowest, String label, String description) {
    this.group = group;
    this.lowest = lowest;
    this.label = label;
    this.description = description;
  }

  public Group group() {
    return group;
  }

  /**
   * The catalogue's suggested lowest built-in role, shown beside each permission. V72 seeded the
   * built-in roles from it, except the ten actions that existed before, which kept the level each
   * install had (so an upgrade changes nothing an analyst could already do).
   */
  public BuiltInRole lowest() {
    return lowest;
  }

  public String label() {
    return label;
  }

  public String description() {
    return description;
  }

  /** Whether a role's set can't change this: everyone sees, only admin manages roles. */
  public boolean fixed() {
    return this == SEE_CAPTURES || this == MANAGE_ROLES;
  }
}
