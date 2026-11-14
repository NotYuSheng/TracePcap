package com.tracepcap.subnets.service;

import com.tracepcap.common.net.LocalityPolicy;
import com.tracepcap.common.net.LocalityRules;
import com.tracepcap.analysis.spi.HostClassificationLookup;
import com.tracepcap.monitor.repository.NetworkSnapshotRepository;
import com.tracepcap.subnets.dto.SubnetDefinitionDto;
import com.tracepcap.subnets.dto.UpsertSubnetRequest;
import com.tracepcap.subnets.entity.SubnetDefinitionEntity;
import com.tracepcap.subnets.repository.SubnetDefinitionRepository;
import java.util.*;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class SubnetService {

  private static final int MIN_HOSTS_PER_SUBNET = 3;
  // Prefix lengths to evaluate (inclusive). /20–/29 covers everything from
  // a 4096-host campus block down to a 8-host micro-segment.
  private static final int MIN_PREFIX = 20;
  private static final int MAX_PREFIX = 29;

  private final LocalityPolicy localityPolicy;
  private final SubnetDefinitionRepository subnetRepo;
  private final HostClassificationLookup hostClassificationLookup;
  private final NetworkSnapshotRepository snapshotRepo;
  private final SubnetStalenessService stalenessService;
  private final com.tracepcap.monitor.repository.NetworkRepository networkRepo;
  private final com.tracepcap.governance.PermissionService permissionService;
  private final com.tracepcap.governance.AuditLogService auditLog;
  private final com.tracepcap.analysis.spi.NetworkSegmentLookup segmentLookup;

  /**
   * What a network entry layers over (#462): its CIDR and, when it's for one of several networks
   * sharing the range, that network's segment. A default's key is its CIDR alone.
   */
  static String layerKey(SubnetDefinitionEntity e) {
    return e.getCidr() + "|" + (e.getSegmentKey() == null ? "" : e.getSegmentKey());
  }

  /** The shared default. */
  public List<SubnetDefinitionDto> list() {
    return subnetRepo.findByNetworkIdIsNullOrderByCidr().stream().map(e -> toDto(e, null)).toList();
  }

  /**
   * The subnets in effect for a network (#915 phase 4): its own entries layered on the default, per
   * CIDR, each with its staleness in that network. Null means the default.
   */
  public List<SubnetDefinitionDto> list(UUID networkId) {
    if (networkId == null) return list();
    java.util.Set<String> defaultCidrs =
        subnetRepo.findByNetworkIdIsNullOrderByCidr().stream().map(SubnetService::layerKey).collect(Collectors.toSet());
    return effective(networkId).stream()
        .sorted(Comparator.comparing(SubnetDefinitionEntity::getCidr))
        .map(e -> {
          SubnetDefinitionDto d = toDto(e, networkId);
          // Where the row comes from, so a network's views edit the right layer.
          boolean own = networkId.equals(e.getNetworkId());
          d.setScope(own ? "network" : "default");
          d.setOverridesDefault(own && defaultCidrs.contains(layerKey(e)));
          return d;
        })
        .toList();
  }

  /** The subnet entities in effect for a network (null = the default). */
  public List<SubnetDefinitionEntity> effective(UUID networkId) {
    List<SubnetDefinitionEntity> defaults = subnetRepo.findByNetworkIdIsNullOrderByCidr();
    if (networkId == null) return defaults;
    return com.tracepcap.common.net.NetworkLayering.effective(
        defaults,
        subnetRepo.findByNetworkIdOrderByCidr(networkId),
        SubnetService::layerKey,
        SubnetDefinitionEntity::isHidden);
  }

  /** The raw subnet entity by id, for callers that need its CIDR (e.g. history lookups). */
  public Optional<SubnetDefinitionEntity> find(Long id) {
    return subnetRepo.findById(id);
  }

  /** Creates or updates a subnet of the shared default. Needs ADDRESS_DEFAULTS; audited. */
  @Transactional
  public SubnetDefinitionDto upsert(UpsertSubnetRequest req) {
    permissionService.require(com.tracepcap.governance.PermissionAction.ADDRESS_DEFAULTS);
    String cidr = normaliseCidr(req.getCidr());
    SubnetDefinitionEntity entity =
        subnetRepo
            .findByCidrAndNetworkIdIsNull(cidr)
            .orElseGet(
                () -> SubnetDefinitionEntity.builder().cidr(cidr).source("MANUAL").build());
    SubnetDefinitionDto before = entity.getId() == null ? null : toDto(entity, null);
    SubnetDefinitionDto after = save(entity, req);
    auditLog.record("subnet.default.set", "subnet", cidr, before, after);
    return after;
  }

  private SubnetDefinitionDto save(SubnetDefinitionEntity entity, UpsertSubnetRequest req) {
    boolean labelChanged = !java.util.Objects.equals(entity.getLabel(), req.getLabel());
    boolean baselined =
        entity.getId() != null && stalenessService.baseline(entity.getId(), req.getNetworkId()).isPresent();
    entity.setLabel(req.getLabel());
    entity.setDescription(req.getDescription());
    entity.setConfirmed(req.isConfirmed());
    if (entity.getId() == null) entity.setSource("MANUAL");
    entity = subnetRepo.save(entity);
    // Confirming a (new or changed) label re-baselines the composition in the network the analyst
    // is looking at, and clears its stale flag there.
    if (req.isConfirmed() && (labelChanged || !baselined)) {
      stalenessService.captureBaseline(entity, req.getNetworkId());
    }
    return toDto(entity, req.getNetworkId());
  }

  /** Dismiss a subnet's stale flag in a network and re-baseline it against the latest snapshot. */
  @Transactional
  public SubnetDefinitionDto dismissStaleness(Long id, UUID networkId) {
    SubnetDefinitionEntity entity =
        subnetRepo
            .findById(id)
            .orElseThrow(
                () ->
                    new com.tracepcap.common.exception.ResourceNotFoundException(
                        "Subnet not found: " + id));
    stalenessService.captureBaseline(entity, networkId);
    return toDto(entity, networkId);
  }

  /** Persists an auto-detected subnet into the shared default. Needs ADDRESS_DEFAULTS; audited. */
  @Transactional
  public SubnetDefinitionDto saveDetected(UpsertSubnetRequest req) {
    permissionService.require(com.tracepcap.governance.PermissionAction.ADDRESS_DEFAULTS);
    String cidr = normaliseCidr(req.getCidr());
    SubnetDefinitionEntity entity =
        subnetRepo
            .findByCidrAndNetworkIdIsNull(cidr)
            .orElseGet(() -> SubnetDefinitionEntity.builder().cidr(cidr).source("AUTO").build());
    if (req.getLabel() != null) entity.setLabel(req.getLabel());
    if (req.getDescription() != null) entity.setDescription(req.getDescription());
    entity.setConfirmed(req.isConfirmed());
    SubnetDefinitionDto saved = toDto(subnetRepo.save(entity), req.getNetworkId());
    auditLog.record("subnet.default.set", "subnet", cidr, null, saved);
    return saved;
  }

  /**
   * Deletes a subnet of the shared default (a network's entries are removed through the network).
   * Needs ADDRESS_DEFAULTS; audited.
   */
  @Transactional
  public void delete(Long id) {
    permissionService.require(com.tracepcap.governance.PermissionAction.ADDRESS_DEFAULTS);
    subnetRepo
        .findById(id)
        .filter(e -> e.getNetworkId() == null)
        .ifPresent(e -> {
          SubnetDefinitionDto before = toDto(e, null);
          subnetRepo.delete(e);
          auditLog.record("subnet.default.delete", "subnet", e.getCidr(), before, null);
        });
  }

  // ── A network's entries (#915 phase 4) ──────────────────────────────────────

  /** A network's view: its own entries (hidden ones included), then the default's it leaves alone. */
  public List<SubnetDefinitionDto> listForNetwork(UUID networkId) {
    requireNetwork(networkId);
    List<SubnetDefinitionEntity> defaults = subnetRepo.findByNetworkIdIsNullOrderByCidr();
    java.util.Set<String> defaultCidrs =
        defaults.stream().map(SubnetService::layerKey).collect(Collectors.toSet());
    List<SubnetDefinitionEntity> own = subnetRepo.findByNetworkIdOrderByCidr(networkId);
    java.util.Set<String> ownCidrs = own.stream().map(SubnetService::layerKey).collect(Collectors.toSet());
    List<SubnetDefinitionDto> out = new java.util.ArrayList<>();
    for (var e : own) {
      SubnetDefinitionDto d = toDto(e, networkId);
      d.setScope("network");
      d.setHidden(e.isHidden());
      d.setOverridesDefault(defaultCidrs.contains(layerKey(e)));
      out.add(d);
    }
    for (var e : defaults) {
      if (ownCidrs.contains(layerKey(e))) continue;
      SubnetDefinitionDto d = toDto(e, networkId);
      d.setScope("default");
      out.add(d);
    }
    out.sort(Comparator.comparing(SubnetDefinitionDto::getCidr)
        .thenComparing(d -> d.getSegmentKey() == null ? "" : d.getSegmentKey()));
    return out;
  }

  /**
   * Sets the network's subnet for a CIDR (override or addition), or hides the default's with
   * {@code req.hidden}. Needs NETWORK_SETTINGS; audited.
   */
  @Transactional
  public SubnetDefinitionDto putForNetwork(UUID networkId, UpsertSubnetRequest req) {
    permissionService.require(com.tracepcap.governance.PermissionAction.NETWORK_SETTINGS);
    requireNetwork(networkId);
    String cidr = normaliseCidr(req.getCidr());
    req.setNetworkId(networkId);
    String segment = req.getSegmentKey() == null || req.getSegmentKey().isBlank() ? null : req.getSegmentKey().trim();
    if (req.isHidden() && segment != null) {
      throw new IllegalArgumentException("Only the range as a whole can hide the default's subnet.");
    }
    if (req.isHidden() && subnetRepo.findByCidrAndNetworkIdIsNull(cidr).isEmpty()) {
      throw new IllegalArgumentException("The default has no subnet " + cidr + " to hide.");
    }
    SubnetDefinitionEntity entity =
        subnetRepo
            .findForSegment(networkId, cidr, segment)
            .orElseGet(() -> SubnetDefinitionEntity.builder().networkId(networkId).cidr(cidr).source("MANUAL")
                .segmentKey(segment).build());
    if (segment != null && req.getSegmentLabel() != null) entity.setSegmentLabel(req.getSegmentLabel());
    SubnetDefinitionDto before = entity.getId() == null ? null : toDto(entity, null);
    entity.setHidden(req.isHidden());
    SubnetDefinitionDto after;
    if (req.isHidden()) {
      entity.setLabel(null);
      entity.setDescription(null);
      entity.setConfirmed(false);
      after = toDto(subnetRepo.save(entity), networkId);
    } else {
      after = save(entity, req);
    }
    after.setScope("network");
    after.setHidden(req.isHidden());
    auditLog.record(
        req.isHidden() ? "subnet.network.hide" : "subnet.network.set",
        "network-subnet", networkId + "/" + cidr + (segment == null ? "" : "~" + segment), before, after);
    return after;
  }

  /** Removes the network's entry, so the default applies again. Needs NETWORK_SETTINGS; audited. */
  @Transactional
  public void deleteForNetwork(UUID networkId, Long id) {
    permissionService.require(com.tracepcap.governance.PermissionAction.NETWORK_SETTINGS);
    SubnetDefinitionEntity e =
        subnetRepo
            .findById(id)
            .filter(r -> networkId.equals(r.getNetworkId()))
            .orElseThrow(() -> new com.tracepcap.common.exception.ResourceNotFoundException("Entry not found: " + id));
    SubnetDefinitionDto before = toDto(e, null);
    subnetRepo.delete(e);
    auditLog.record("subnet.network.revert", "network-subnet", networkId + "/" + e.getCidr(), before, null);
  }

  private void requireNetwork(UUID networkId) {
    if (networkId == null || !networkRepo.existsById(networkId)) {
      throw new com.tracepcap.common.exception.ResourceNotFoundException("Network not found: " + networkId);
    }
  }

  /**
   * Detect subnets from a single snapshot file using variable-length density scoring.
   * Does NOT persist.
   */
  public List<SubnetDefinitionDto> detectFromFile(UUID fileId) {
    LocalityRules locality = localityPolicy.currentRules();
    List<Long> ipInts =
        hostClassificationLookup.classifiedHosts(fileId).stream()
            .map(h -> h.ip())
            .filter(locality::isLocal)
            .map(ip -> parseIp(ip))
            .filter(v -> v != null && v >= 0)
            .distinct()
            .collect(Collectors.toList());

    return splitBySegment(selectCandidates(ipInts, 1, 1), segmentLookup.segments(fileId), 1, 1);
  }

  /**
   * A detected range that more than one network uses (#462) becomes one candidate per network, each
   * counting that network's own addresses in it. Other candidates are left as they are.
   */
  static List<SubnetDefinitionDto> splitBySegment(
      List<SubnetDefinitionDto> candidates,
      List<com.tracepcap.analysis.spi.NetworkSegmentLookup.Segment> segments,
      int snapshotsSeen,
      int totalSnapshots) {
    List<com.tracepcap.analysis.spi.NetworkSegmentLookup.Segment> sharing =
        segments.stream().filter(com.tracepcap.analysis.spi.NetworkSegmentLookup.Segment::sharesRange).toList();
    if (sharing.isEmpty()) return candidates;
    List<SubnetDefinitionDto> out = new ArrayList<>();
    for (SubnetDefinitionDto c : candidates) {
      long[] range;
      try {
        range = CidrRange.of(c.getCidr());
      } catch (Exception e) {
        out.add(c);
        continue;
      }
      List<SubnetDefinitionDto> split = new ArrayList<>();
      for (var seg : sharing) {
        long n = seg.addresses().stream().map(SubnetService::parseIp).filter(v -> v >= range[0] && v <= range[1]).count();
        if (n == 0) continue;
        split.add(
            SubnetDefinitionDto.builder()
                .cidr(c.getCidr())
                .segmentKey(seg.key())
                .segmentLabel(seg.label())
                .source("AUTO")
                .confirmed(false)
                .hostCount((int) n)
                .densityScore(c.getDensityScore())
                .snapshotsSeen(snapshotsSeen)
                .totalSnapshots(totalSnapshots)
                .build());
      }
      if (split.size() > 1) out.addAll(split);
      else out.add(c);
    }
    return out;
  }

  /**
   * Detect subnets across all snapshots of a network, adding cross-snapshot
   * consistency scores. Does NOT persist.
   */
  public List<SubnetDefinitionDto> detectFromNetwork(UUID networkId) {
    List<UUID> fileIds =
        snapshotRepo.findByNetworkIdOrderBySnapshotOrderAsc(networkId).stream()
            .filter(s -> s.getFile() != null)
            .map(s -> s.getFile().getId())
            .collect(Collectors.toList());

    int totalSnapshots = fileIds.size();
    if (totalSnapshots == 0) return Collections.emptyList();

    // Per-snapshot detection: cidr -> number of snapshots it appeared in
    Map<String, Integer> cidrSnapshotCount = new LinkedHashMap<>();

    // The networks across all snapshots (#462), merged by key: the same VLAN or DHCP server in
    // every weekly capture is one network.
    Map<String, com.tracepcap.analysis.spi.NetworkSegmentLookup.Segment> segmentsByKey = new LinkedHashMap<>();
    for (UUID fileId : fileIds) {
      List<SubnetDefinitionDto> snapCandidates = detectFromFile(fileId);
      for (SubnetDefinitionDto c : snapCandidates) {
        cidrSnapshotCount.merge(candidateKey(c), 1, Integer::sum);
      }
      for (var seg : segmentLookup.segments(fileId)) {
        segmentsByKey.merge(seg.key(), seg, (a, b) -> {
          java.util.Set<String> addrs = new java.util.LinkedHashSet<>(a.addresses());
          addrs.addAll(b.addresses());
          java.util.Set<String> macs = new java.util.LinkedHashSet<>(a.macs());
          macs.addAll(b.macs());
          return new com.tracepcap.analysis.spi.NetworkSegmentLookup.Segment(
              a.key(), a.label(), a.cidr(), addrs, macs, a.sharesRange() || b.sharesRange());
        });
      }
    }

    // Re-run density scoring on the union of all IPs for final hostCount/densityScore
    LocalityRules locality = localityPolicy.currentRules();
    List<Long> allIps =
        fileIds.stream()
            .flatMap(fid -> hostClassificationLookup.classifiedHosts(fid).stream())
            .map(h -> h.ip())
            .filter(locality::isLocal)
            .map(ip -> parseIp(ip))
            .filter(v -> v != null && v >= 0)
            .distinct()
            .collect(Collectors.toList());

    List<SubnetDefinitionDto> base =
        splitBySegment(selectCandidates(allIps, 1, 1), new ArrayList<>(segmentsByKey.values()), 1, 1);

    // Merge consistency scores in
    List<SubnetDefinitionDto> result = new ArrayList<>();
    for (SubnetDefinitionDto c : base) {
      int seen = cidrSnapshotCount.getOrDefault(candidateKey(c), 0);
      result.add(
          SubnetDefinitionDto.builder()
              .cidr(c.getCidr())
              .segmentKey(c.getSegmentKey())
              .segmentLabel(c.getSegmentLabel())
              .source("AUTO")
              .confirmed(false)
              .hostCount(c.getHostCount())
              .densityScore(c.getDensityScore())
              .snapshotsSeen(seen)
              .totalSnapshots(totalSnapshots)
              .build());
    }

    // Sort: consistency descending, then density descending, then CIDR
    result.sort(
        Comparator.comparingDouble(
                (SubnetDefinitionDto d) ->
                    d.getSnapshotsSeen() == null ? 0 : d.getSnapshotsSeen())
            .reversed()
            .thenComparingDouble(
                (SubnetDefinitionDto d) ->
                    d.getDensityScore() == null ? 0 : d.getDensityScore())
            .reversed()
            .thenComparing(SubnetDefinitionDto::getCidr));

    return result;
  }

  private static String candidateKey(SubnetDefinitionDto c) {
    return c.getCidr() + "|" + (c.getSegmentKey() == null ? "" : c.getSegmentKey());
  }

  // ── core detection ────────────────────────────────────────────────────────

  /**
   * Given a list of IP integers, score all candidate CIDRs (/20–/29), greedily
   * select non-overlapping winners by density, and return them sorted by density.
   */
  private List<SubnetDefinitionDto> selectCandidates(
      List<Long> ipInts, int snapshotsSeen, int totalSnapshots) {

    if (ipInts.isEmpty()) return Collections.emptyList();

    // Build all candidate CIDRs and count how many observed IPs fall inside each
    // candidate: cidr string -> {networkInt, prefixLen, hostCount, capacity}
    Map<String, long[]> scored = new LinkedHashMap<>();

    for (long ip : ipInts) {
      for (int prefix = MIN_PREFIX; prefix <= MAX_PREFIX; prefix++) {
        long mask = prefixToMask(prefix);
        long network = ip & mask;
        String cidr = intToIp(network) + "/" + prefix;
        final long fNetwork = network;
        final int fPrefix = prefix;
        scored.computeIfAbsent(cidr, k -> new long[] {fNetwork, fPrefix, 0, 1L << (32 - fPrefix)});
        scored.get(cidr)[2]++;
      }
    }

    // Filter by minimum host threshold
    List<Map.Entry<String, long[]>> candidates =
        scored.entrySet().stream()
            .filter(e -> e.getValue()[2] >= MIN_HOSTS_PER_SUBNET)
            .sorted(
                Comparator.comparingDouble(
                        (Map.Entry<String, long[]> e) ->
                            (double) e.getValue()[2] / e.getValue()[3])
                    .reversed()
                    .thenComparingInt(e -> (int) e.getValue()[1]) // prefer tighter prefix
                    .thenComparing(Map.Entry::getKey))
            .collect(Collectors.toList());

    // Greedy non-overlapping selection: pick highest-density first, skip any
    // candidate whose range is already fully covered by a selected one
    List<SubnetDefinitionDto> selected = new ArrayList<>();
    List<long[]> chosen = new ArrayList<>(); // [networkInt, mask]

    for (Map.Entry<String, long[]> entry : candidates) {
      long[] v = entry.getValue(); // [network, prefix, hostCount, capacity]
      long mask = prefixToMask((int) v[1]);

      // Skip if this candidate is entirely contained within an already-chosen subnet
      // (i.e. a smaller subnet that's a subset of something already selected)
      boolean dominated = false;
      for (long[] ch : chosen) {
        if ((v[0] & ch[1]) == ch[0] && mask != ch[1]) {
          // candidate is a strict subset of an already-chosen CIDR
          dominated = true;
          break;
        }
      }
      if (dominated) continue;

      // Also skip if candidate fully contains an already-chosen subnet (a broader
      // supernet of something already chosen) — prefer the more specific one
      boolean isSupernet = false;
      for (long[] ch : chosen) {
        if ((ch[0] & mask) == v[0] && mask != ch[1]) {
          isSupernet = true;
          break;
        }
      }
      if (isSupernet) continue;

      double density = (double) v[2] / v[3];
      selected.add(
          SubnetDefinitionDto.builder()
              .cidr(entry.getKey())
              .source("AUTO")
              .confirmed(false)
              .hostCount((int) v[2])
              .densityScore(Math.round(density * 1000.0) / 1000.0)
              .snapshotsSeen(snapshotsSeen)
              .totalSnapshots(totalSnapshots)
              .build());
      chosen.add(new long[] {v[0], mask});
    }

    return selected;
  }

  // ── helpers ──────────────────────────────────────────────────────────────

  /** {@code networkId} picks whose staleness baseline to show; null shows none. */
  private SubnetDefinitionDto toDto(SubnetDefinitionEntity e, UUID networkId) {
    var b = stalenessService.baseline(e.getId(), networkId).orElse(null);
    return SubnetDefinitionDto.builder()
        .id(e.getId())
        .cidr(e.getCidr())
        .segmentKey(e.getSegmentKey())
        .segmentLabel(e.getSegmentLabel())
        .label(e.getLabel())
        .description(e.getDescription())
        .source(e.getSource())
        .confirmed(e.isConfirmed())
        .labeledAt(b == null ? null : b.getLabeledAt())
        .staleSince(b == null ? null : b.getStaleSince())
        .staleFields(b == null ? null : b.getStaleFields())
        .createdAt(e.getCreatedAt())
        .updatedAt(e.getUpdatedAt())
        .build();
  }

  /** Returns the IP as a long (0–4294967295), or -1 on parse failure. */
  private static long parseIp(String ip) {
    try {
      String[] p = ip.split("\\.");
      if (p.length != 4) return -1;
      long v = 0;
      for (String part : p) {
        int oct = Integer.parseInt(part);
        if (oct < 0 || oct > 255) return -1;
        v = (v << 8) | oct;
      }
      return v;
    } catch (NumberFormatException e) {
      return -1;
    }
  }

  private static long prefixToMask(int prefix) {
    return prefix == 0 ? 0L : (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
  }

  private static String intToIp(long ip) {
    return ((ip >> 24) & 0xFF) + "." + ((ip >> 16) & 0xFF) + "." + ((ip >> 8) & 0xFF) + "." + (ip & 0xFF);
  }

  /** Delegates to the shared predicate so all four call sites agree (#694). */


  private static final java.util.regex.Pattern CIDR_PATTERN =
      java.util.regex.Pattern.compile(
          "^(\\d{1,3}\\.){3}\\d{1,3}/([0-9]|[1-2]\\d|3[0-2])$");

  private static String normaliseCidr(String cidr) {
    if (cidr == null || cidr.isBlank()) throw new IllegalArgumentException("CIDR must not be blank");
    cidr = cidr.trim();
    if (!CIDR_PATTERN.matcher(cidr).matches()) {
      throw new IllegalArgumentException("Invalid CIDR format: " + cidr);
    }
    // Verify each octet is 0–255
    String[] parts = cidr.split("[./]");
    for (int i = 0; i < 4; i++) {
      int octet = Integer.parseInt(parts[i]);
      if (octet < 0 || octet > 255) throw new IllegalArgumentException("Invalid CIDR format: " + cidr);
    }
    return cidr;
  }
}
