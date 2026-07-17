package com.tracepcap.analysis.spi;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Read port for per-file host classifications (#512 slices 5–6b): the scan output downstream stages
 * consume without reaching into {@code analysis}' repositories or entities.
 *
 * <p>Two record shapes, deliberately not merged:
 *
 * <ul>
 *   <li>{@link ClassifiedHost} — the <em>contest</em>. Winner plus runner-up scores, for
 *       adjudication, which needs to know how close second place was rather than just the argmax.
 *   <li>{@link HostFacts} — the <em>description</em>. What we observed about a host, for display
 *       and for building LLM prompt context. Carries no scores: a consumer rendering a MAC address
 *       has no business seeing the tie-break internals.
 * </ul>
 *
 * Keeping them apart is the point — one fat record serving both would hand every consumer fields it
 * must ignore, which is how a port silently becomes a repository again.
 */
public interface HostClassificationLookup {

  record ClassifiedHost(
      String ip,
      String deviceType,
      int confidence,
      Integer winnerScore,
      String runnerUpType,
      Integer runnerUpScore) {}

  /**
   * Descriptive facts observed about one host in one file.
   *
   * <p>Nullability mirrors the schema rather than being uniform, because consumers building display
   * text or prompt context need to know which fields need a guard:
   *
   * <ul>
   *   <li><b>Never null:</b> {@code ip}, {@code deviceType}, {@code confidence} — all {@code NOT
   *       NULL} columns. A host always classifies as <em>something</em> (worst case {@code UNKNOWN}
   *       at low confidence), so there is no "no device type" state to guard against.
   *   <li><b>Never null, may be empty:</b> {@code serviceRoles} — already split from its stored
   *       comma-joined form, and immutable.
   *   <li><b>Nullable:</b> {@code mac}, {@code manufacturer}, {@code hostname}, {@code
   *       hostnameSource}, {@code ttl} — the capture may simply not reveal these.
   * </ul>
   */
  record HostFacts(
      String ip,
      String mac,
      String manufacturer,
      String hostname,
      String hostnameSource,
      Integer ttl,
      String deviceType,
      int confidence,
      List<String> serviceRoles) {}

  /** Never contains null elements — the adapter maps each persisted row to a fresh record. */
  List<ClassifiedHost> classifiedHosts(UUID fileId);

  /** Every host in the file, in persistence order. Never contains null elements. */
  List<HostFacts> hostFacts(UUID fileId);

  /**
   * The host holding this IP in this file, if any.
   *
   * <p>A file may legitimately hold more than one row for an IP (two MACs claiming it during an ARP
   * conflict); this returns the first by insertion order, chosen deterministically so repeated
   * reads agree.
   */
  Optional<HostFacts> hostFactsByIp(UUID fileId, String ip);

  /** As {@link #hostFactsByIp}, keyed by MAC. The match is case-insensitive. */
  Optional<HostFacts> hostFactsByMac(UUID fileId, String mac);

  /**
   * How many hosts the file holds — counted in the database, for callers that want the number rather
   * than the hosts.
   */
  long hostCount(UUID fileId);
}
