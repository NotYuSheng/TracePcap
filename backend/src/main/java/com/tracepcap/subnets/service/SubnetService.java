package com.lanturn.subnets.service;

import com.lanturn.analysis.repository.HostClassificationRepository;
import com.lanturn.monitor.repository.NetworkSnapshotRepository;
import com.lanturn.subnets.dto.SubnetDefinitionDto;
import com.lanturn.subnets.dto.UpsertSubnetRequest;
import com.lanturn.subnets.entity.SubnetDefinitionEntity;
import com.lanturn.subnets.repository.SubnetDefinitionRepository;
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

  private final SubnetDefinitionRepository subnetRepo;
  private final HostClassificationRepository hostClassRepo;
  private final NetworkSnapshotRepository snapshotRepo;

  public List<SubnetDefinitionDto> list() {
    return subnetRepo.findAll().stream()
        .sorted(Comparator.comparing(SubnetDefinitionEntity::getCidr))
        .map(this::toDto)
        .collect(Collectors.toList());
  }

  @Transactional
  public SubnetDefinitionDto upsert(UpsertSubnetRequest req) {
    String cidr = normaliseCidr(req.getCidr());
    SubnetDefinitionEntity entity =
        subnetRepo
            .findByCidr(cidr)
            .orElseGet(
                () -> SubnetDefinitionEntity.builder().cidr(cidr).source("MANUAL").build());
    entity.setLabel(req.getLabel());
    entity.setDescription(req.getDescription());
    entity.setConfirmed(req.isConfirmed());
    if (entity.getId() == null) entity.setSource("MANUAL");
    return toDto(subnetRepo.save(entity));
  }

  @Transactional
  public SubnetDefinitionDto saveDetected(UpsertSubnetRequest req) {
    String cidr = normaliseCidr(req.getCidr());
    SubnetDefinitionEntity entity =
        subnetRepo
            .findByCidr(cidr)
            .orElseGet(() -> SubnetDefinitionEntity.builder().cidr(cidr).source("AUTO").build());
    if (req.getLabel() != null) entity.setLabel(req.getLabel());
    if (req.getDescription() != null) entity.setDescription(req.getDescription());
    entity.setConfirmed(req.isConfirmed());
    return toDto(subnetRepo.save(entity));
  }

  @Transactional
  public void delete(Long id) {
    subnetRepo.deleteById(id);
  }

  /**
   * Detect subnets from a single snapshot file using variable-length density scoring.
   * Does NOT persist.
   */
  public List<SubnetDefinitionDto> detectFromFile(UUID fileId) {
    List<Long> ipInts =
        hostClassRepo.findByFileId(fileId).stream()
            .map(h -> h.getIp())
            .filter(ip -> isPrivate(ip))
            .map(ip -> parseIp(ip))
            .filter(v -> v != null && v >= 0)
            .distinct()
            .collect(Collectors.toList());

    return selectCandidates(ipInts, 1, 1);
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

    for (UUID fileId : fileIds) {
      List<SubnetDefinitionDto> snapCandidates = detectFromFile(fileId);
      for (SubnetDefinitionDto c : snapCandidates) {
        cidrSnapshotCount.merge(c.getCidr(), 1, Integer::sum);
      }
    }

    // Re-run density scoring on the union of all IPs for final hostCount/densityScore
    List<Long> allIps =
        fileIds.stream()
            .flatMap(fid -> hostClassRepo.findByFileId(fid).stream())
            .map(h -> h.getIp())
            .filter(ip -> isPrivate(ip))
            .map(ip -> parseIp(ip))
            .filter(v -> v != null && v >= 0)
            .distinct()
            .collect(Collectors.toList());

    List<SubnetDefinitionDto> base = selectCandidates(allIps, 1, 1);

    // Merge consistency scores in
    List<SubnetDefinitionDto> result = new ArrayList<>();
    for (SubnetDefinitionDto c : base) {
      int seen = cidrSnapshotCount.getOrDefault(c.getCidr(), 0);
      result.add(
          SubnetDefinitionDto.builder()
              .cidr(c.getCidr())
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

  private SubnetDefinitionDto toDto(SubnetDefinitionEntity e) {
    return SubnetDefinitionDto.builder()
        .id(e.getId())
        .cidr(e.getCidr())
        .label(e.getLabel())
        .description(e.getDescription())
        .source(e.getSource())
        .confirmed(e.isConfirmed())
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

  private static boolean isPrivate(String ip) {
    if (ip == null) return false;
    return ip.startsWith("10.")
        || ip.startsWith("192.168.")
        || ip.matches("172\\.(1[6-9]|2\\d|3[01])\\..*");
  }

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
