package com.tracepcap.knowledge.spi;

/**
 * How directly a knowledge artifact is known — the same three-way grading the Extract stage applies
 * to facts (#512), carried onto the knowledge board so downstream consumers (deterministic checks,
 * the narrator) can weigh a claim by how much it can be trusted.
 *
 * <p>A conclusion built from {@link #MEASURED} facts outranks one built from {@link #REPORTED} or
 * {@link #INFERRED} ones.
 */
public enum Grade {
  /** The traffic itself exhibited it (a Kerberos AS-REQ principal, a byte count). Strongest. */
  MEASURED,
  /** A party asserted it on the wire (a DHCP hostname, an LDAP display name) — testimony; parties lie. */
  REPORTED,
  /** A tool judged it (nDPI's app name, Suricata's verdict, a device-type vote) — a guess with error modes. */
  INFERRED
}
