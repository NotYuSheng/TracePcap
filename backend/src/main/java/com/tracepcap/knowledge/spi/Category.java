package com.tracepcap.knowledge.spi;

/**
 * One thing an investigation can have something to say about (the investigation framework, see
 * docs/architecture/investigation-framework.rst). The set is fixed, so a category no check covers
 * still shows, and "never looked" stops reading the same as "checked, found nothing".
 *
 * <p>Three axes: what the capture can show ({@link Axis#CONTEXT}), the roles hosts play
 * ({@link Axis#ENTITY}, after the Diamond Model's corners plus roles it has none for), and what
 * happened ({@link Axis#ACTIVITY}, the fourteen MITRE ATT&amp;CK Enterprise tactics).
 */
public enum Category {
  // Capture context: frames every other answer.
  VANTAGE_POINT(Axis.CONTEXT, "vantage-point", "Vantage point", null, Visibility.WIRE, null),
  COMPLETENESS(Axis.CONTEXT, "completeness", "Completeness", null, Visibility.WIRE, null),
  TIME_SPAN(Axis.CONTEXT, "time-span", "Time span", null, Visibility.WIRE, null),

  // Entities: what a host is.
  VICTIM(Axis.ENTITY, "victim", "Victim", null, Visibility.WIRE, null),
  SIGNED_IN_USER(Axis.ENTITY, "signed-in-user", "Who's signed in", null, Visibility.WIRE, null),
  C2_SERVER(Axis.ENTITY, "c2-server", "C2 server", null, Visibility.WIRE, null),
  REMOTE_ACCESS_SERVER(
      Axis.ENTITY, "remote-access-server", "Remote-access server", null, Visibility.WIRE, null),
  SCANNER(Axis.ENTITY, "scanner", "Scanner", null, Visibility.WIRE, null),
  HONEYPOT(Axis.ENTITY, "honeypot", "Honeypot", null, Visibility.WIRE, null),
  ADVERSARY(Axis.ENTITY, "adversary", "Adversary", null, Visibility.NEVER,
      "who is behind an attack isn't visible in traffic"),

  // Activities: the ATT&CK tactics, in the matrix's order.
  RECONNAISSANCE(
      Axis.ACTIVITY, "reconnaissance", "Reconnaissance", "TA0043", Visibility.WIRE, null),
  RESOURCE_DEVELOPMENT(Axis.ACTIVITY, "resource-development", "Resource Development", "TA0042",
      Visibility.NEVER, "an attacker's preparation happens before and away from this network"),
  INITIAL_ACCESS(
      Axis.ACTIVITY, "initial-access", "Initial Access", "TA0001", Visibility.WIRE, null),
  EXECUTION(Axis.ACTIVITY, "execution", "Execution", "TA0002", Visibility.PARTLY, null),
  PERSISTENCE(Axis.ACTIVITY, "persistence", "Persistence", "TA0003", Visibility.RARELY,
      "happens on the host, and rarely shows on the wire"),
  PRIVILEGE_ESCALATION(Axis.ACTIVITY, "privilege-escalation", "Privilege Escalation", "TA0004",
      Visibility.RARELY, "happens on the host, and rarely shows on the wire"),
  DEFENSE_EVASION(
      Axis.ACTIVITY, "defense-evasion", "Defense Evasion", "TA0005", Visibility.WIRE, null),
  CREDENTIAL_ACCESS(
      Axis.ACTIVITY, "credential-access", "Credential Access", "TA0006", Visibility.WIRE, null),
  DISCOVERY(Axis.ACTIVITY, "discovery", "Discovery", "TA0007", Visibility.WIRE, null),
  LATERAL_MOVEMENT(
      Axis.ACTIVITY, "lateral-movement", "Lateral Movement", "TA0008", Visibility.WIRE, null),
  COLLECTION(Axis.ACTIVITY, "collection", "Collection", "TA0009", Visibility.PARTLY, null),
  COMMAND_AND_CONTROL(Axis.ACTIVITY, "command-and-control", "Command and Control", "TA0011",
      Visibility.WIRE, null),
  EXFILTRATION(Axis.ACTIVITY, "exfiltration", "Exfiltration", "TA0010", Visibility.WIRE, null),
  IMPACT(Axis.ACTIVITY, "impact", "Impact", "TA0040", Visibility.PARTLY, null);

  /** Which of the framework's three axes a category sits on. */
  public enum Axis {
    CONTEXT,
    ENTITY,
    ACTIVITY
  }

  /** How much of a category a packet capture can show at all. */
  public enum Visibility {
    /** Shows in traffic when it happens. */
    WIRE,
    /** Some of it shows in traffic. */
    PARTLY,
    /** Mostly happens on a host; not observable unless a check concludes it anyway. */
    RARELY,
    /** Never in traffic: always not observable. */
    NEVER
  }

  private final Axis axis;
  private final String key;
  private final String label;
  private final String attackId;
  private final Visibility visibility;
  private final String unseenReason;

  Category(
      Axis axis, String key, String label, String attackId, Visibility visibility,
      String unseenReason) {
    this.axis = axis;
    this.key = key;
    this.label = label;
    this.attackId = attackId;
    this.visibility = visibility;
    this.unseenReason = unseenReason;
  }

  public Axis axis() {
    return axis;
  }

  /** Stable kebab-case key, as the API and the frontend name it. */
  public String key() {
    return key;
  }

  public String label() {
    return label;
  }

  /** The ATT&amp;CK tactic id for an activity ({@code TA0011}); null on the other axes. */
  public String attackId() {
    return attackId;
  }

  public Visibility visibility() {
    return visibility;
  }

  /** Why a capture can't show it, for {@link Visibility#RARELY} and {@link Visibility#NEVER}. */
  public String unseenReason() {
    return unseenReason;
  }
}
