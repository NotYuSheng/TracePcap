package com.tracepcap.knowledge.spi;

/**
 * The kinds of thing that can be a node on the knowledge board. Deliberately small and extensible —
 * a new contributor that needs a new kind adds a value here, and presenters render generically off
 * the type.
 */
public enum EntityType {
  /** An internal host observed in the capture, keyed by IP. */
  HOST,
  /** A person / account (a Windows sign-in, say), keyed by username. */
  USER,
  /** An external party the capture talked to, keyed by IP. */
  EXTERNAL_SERVICE,
  /** A malware family named by a detector (Suricata, a signature). */
  MALWARE
}
