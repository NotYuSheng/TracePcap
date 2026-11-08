package com.tracepcap.policy.service;

import com.tracepcap.policy.dto.CustomPrivateRangeDto;
import com.tracepcap.policy.entity.CustomPrivateRangeEntity;
import com.tracepcap.policy.entity.IpClassification;
import com.tracepcap.policy.repository.CustomPrivateRangeRepository;
import java.net.InetAddress;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomPrivateRangeService {

  private final CustomPrivateRangeRepository repository;
  private final com.tracepcap.governance.PermissionService permissionService;
  private final com.tracepcap.governance.AuditLogService auditLog;

  private record ParsedCidr(byte[] networkBytes, int prefixLen) {}
  private final ConcurrentHashMap<String, Optional<ParsedCidr>> cidrCache =
      new ConcurrentHashMap<>();

  // Matches dotted-decimal IPv4 or hex-colon IPv6 — rejects hostnames before DNS lookup
  private static final Pattern NUMERIC_IP =
      Pattern.compile("^(\\d{1,3}\\.){3}\\d{1,3}$|^[0-9a-fA-F]*:[0-9a-fA-F:.]*$");

  /** The shared default. */
  public List<CustomPrivateRangeDto> list() {
    return repository.findByNetworkIdIsNullOrderByCreatedAtDesc().stream()
        .map(CustomPrivateRangeService::toDto)
        .collect(Collectors.toList());
  }

  private static CustomPrivateRangeDto toDto(CustomPrivateRangeEntity e) {
    return CustomPrivateRangeDto.builder()
        .id(e.getId())
        .cidr(e.getCidr())
        .classification(e.getClassification().name())
        .build();
  }

  /** A bare IP or CIDR, validated and normalised (bare IPs become /32 or /128). */
  static String normaliseCidr(String raw) {
    if (raw == null || raw.isBlank()) throw new IllegalArgumentException("A CIDR is required");
    String cidr = raw.trim();
    // Determine IP and optional prefix parts — indexOf avoids split edge-case with bare "/"
    int slashIdx = cidr.indexOf('/');
    String ipPart = slashIdx >= 0 ? cidr.substring(0, slashIdx).trim() : cidr;
    // Reject hostnames — only numeric IPs are accepted to prevent DNS resolution
    if (!NUMERIC_IP.matcher(ipPart).matches()) {
      throw new IllegalArgumentException("Invalid IP address: " + ipPart);
    }
    // Normalise bare IP to /32 or /128
    if (!cidr.contains("/")) {
      try {
        InetAddress addr = InetAddress.getByName(ipPart);
        cidr = addr.getHostAddress() + (addr.getAddress().length == 4 ? "/32" : "/128");
      } catch (Exception e) {
        throw new IllegalArgumentException("Invalid IP address: " + ipPart);
      }
    }
    // Validate CIDR
    String[] parts = cidr.split("/");
    if (parts.length != 2) throw new IllegalArgumentException("Invalid CIDR format: " + cidr);
    try {
      InetAddress addr = InetAddress.getByName(parts[0].trim());
      int prefixMax = (addr.getAddress().length == 4) ? 32 : 128;
      int prefix = Integer.parseInt(parts[1].trim());
      if (prefix < 0 || prefix > prefixMax)
        throw new IllegalArgumentException("Prefix length out of range for " + cidr);
      cidr = addr.getHostAddress() + "/" + prefix;
    } catch (IllegalArgumentException e) {
      throw e;
    } catch (Exception e) {
      throw new IllegalArgumentException("Invalid IP address in CIDR: " + cidr);
    }
    return cidr;
  }

  /** Adds an entry to the shared default. */
  public CustomPrivateRangeDto create(CustomPrivateRangeDto dto) {
    String cidr = normaliseCidr(dto.getCidr());
    IpClassification classification = parseClassification(dto.getClassification());
    CustomPrivateRangeEntity entity = CustomPrivateRangeEntity.builder()
        .cidr(cidr)
        .classification(classification)
        .createdAt(LocalDateTime.now())
        .build();
    entity = repository.save(entity);
    cidrCache.clear();
    return toDto(entity);
  }

  /** Defaults to PRIVATE for backward compatibility; rejects anything else. */
  private IpClassification parseClassification(String raw) {
    if (raw == null || raw.isBlank()) return IpClassification.PRIVATE;
    try {
      return IpClassification.valueOf(raw.trim().toUpperCase());
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("Classification must be PRIVATE or PUBLIC");
    }
  }

  /** Deletes an entry of the shared default. A network's entries are removed through the network. */
  public void delete(Long id) {
    repository
        .findById(id)
        .filter(e -> e.getNetworkId() == null)
        .ifPresent(repository::delete);
    cidrCache.clear();
  }

  /** The shared default, for batch classification. */
  public List<CustomPrivateRangeEntity> loadRanges() {
    return repository.findByNetworkIdIsNullOrderByCreatedAtDesc();
  }

  /**
   * The ranges in effect for a network (#915 phase 4): its own entries layered on the default,
   * per CIDR. Null means the default.
   */
  public List<CustomPrivateRangeEntity> loadRanges(UUID networkId) {
    if (networkId == null) return loadRanges();
    return com.tracepcap.common.net.NetworkLayering.effective(
        loadRanges(),
        repository.findByNetworkIdOrderByCreatedAtDesc(networkId),
        CustomPrivateRangeEntity::getCidr,
        CustomPrivateRangeEntity::isHidden);
  }

  // ── A network's entries (#915 phase 4) ──────────────────────────────────────

  /**
   * A network's view: its own entries (hidden ones included, so they can be reverted), then the
   * default's entries it doesn't override or hide.
   */
  public List<CustomPrivateRangeDto> listForNetwork(UUID networkId) {
    List<CustomPrivateRangeEntity> defaults = loadRanges();
    java.util.Set<String> defaultCidrs =
        defaults.stream().map(CustomPrivateRangeEntity::getCidr).collect(Collectors.toSet());
    List<CustomPrivateRangeEntity> own = repository.findByNetworkIdOrderByCreatedAtDesc(networkId);
    java.util.Set<String> ownCidrs = own.stream().map(CustomPrivateRangeEntity::getCidr).collect(Collectors.toSet());
    List<CustomPrivateRangeDto> out = new java.util.ArrayList<>();
    for (var e : own) {
      CustomPrivateRangeDto d = toDto(e);
      d.setScope("network");
      d.setHidden(e.isHidden());
      d.setOverridesDefault(defaultCidrs.contains(e.getCidr()));
      out.add(d);
    }
    for (var e : defaults) {
      if (ownCidrs.contains(e.getCidr())) continue;
      CustomPrivateRangeDto d = toDto(e);
      d.setScope("default");
      out.add(d);
    }
    return out;
  }

  /**
   * Sets the network's entry for a CIDR: an override or an addition, or, with {@code hidden}, hides
   * the default's entry in this network. Needs NETWORK_SETTINGS; audited.
   */
  @org.springframework.transaction.annotation.Transactional
  public CustomPrivateRangeDto putForNetwork(UUID networkId, CustomPrivateRangeDto dto, boolean hidden) {
    permissionService.require(com.tracepcap.governance.PermissionAction.NETWORK_SETTINGS);
    String cidr = normaliseCidr(dto.getCidr());
    IpClassification classification;
    if (hidden) {
      CustomPrivateRangeEntity def =
          loadRanges().stream()
              .filter(e -> e.getCidr().equals(cidr))
              .findFirst()
              .orElseThrow(() -> new IllegalArgumentException("The default has no entry for " + cidr + " to hide."));
      classification = def.getClassification();
    } else {
      classification = parseClassification(dto.getClassification());
    }
    CustomPrivateRangeEntity e =
        repository
            .findByNetworkIdAndCidr(networkId, cidr)
            .orElseGet(() -> CustomPrivateRangeEntity.builder().networkId(networkId).cidr(cidr).build());
    CustomPrivateRangeDto before = e.getId() == null ? null : toDto(e);
    e.setClassification(classification);
    e.setHidden(hidden);
    e.setCreatedAt(LocalDateTime.now());
    e = repository.save(e);
    cidrCache.clear();
    CustomPrivateRangeDto after = toDto(e);
    after.setScope("network");
    after.setHidden(hidden);
    auditLog.record(
        hidden ? "private-range.network.hide" : "private-range.network.set",
        "network-private-range", networkId + "/" + cidr, before, after);
    return after;
  }

  /** Removes the network's entry, so the default applies again. Needs NETWORK_SETTINGS; audited. */
  @org.springframework.transaction.annotation.Transactional
  public void deleteForNetwork(UUID networkId, Long id) {
    permissionService.require(com.tracepcap.governance.PermissionAction.NETWORK_SETTINGS);
    CustomPrivateRangeEntity e =
        repository
            .findById(id)
            .filter(r -> networkId.equals(r.getNetworkId()))
            .orElseThrow(() -> new com.tracepcap.common.exception.ResourceNotFoundException("Entry not found: " + id));
    repository.delete(e);
    cidrCache.clear();
    auditLog.record("private-range.network.revert", "network-private-range", networkId + "/" + e.getCidr(), toDto(e), null);
  }

  /**
   * Returns true if the IP falls within any of the preloaded custom private ranges.
   * Call {@link #loadRanges()} once and reuse the list across many IP checks.
   */
  public boolean isOverriddenPrivate(String ip, List<CustomPrivateRangeEntity> ranges) {
    if (ip == null || ranges.isEmpty()) return false;
    byte[] addrBytes = resolveAddress(ip);
    if (addrBytes == null) return false;
    for (CustomPrivateRangeEntity range : ranges) {
      if (inCidrBytes(addrBytes, range.getCidr())) return true;
    }
    return false;
  }

  /** Verdict for an IP against the classification overrides. */
  public enum Override {
    FORCE_PRIVATE,
    FORCE_PUBLIC,
    NONE
  }

  /**
   * Returns the classification override that applies to an IP, or {@link Override#NONE} if no range
   * matches. When multiple ranges match, the first in the provided list wins (ranges are ordered
   * most-recent-first), so a newer override takes precedence.
   */
  public Override overrideFor(String ip, List<CustomPrivateRangeEntity> ranges) {
    if (ip == null || ranges == null || ranges.isEmpty()) return Override.NONE;
    byte[] addrBytes = resolveAddress(ip);
    if (addrBytes == null) return Override.NONE;
    for (CustomPrivateRangeEntity range : ranges) {
      if (inCidrBytes(addrBytes, range.getCidr())) {
        return range.getClassification() == IpClassification.PUBLIC
            ? Override.FORCE_PUBLIC
            : Override.FORCE_PRIVATE;
      }
    }
    return Override.NONE;
  }

  /**
   * Returns true if the IP falls within any of the provided CIDR strings.
   * Used by callers that work with plain CIDR lists rather than entity objects.
   */
  public boolean isInCidrs(String ip, List<String> cidrs) {
    if (ip == null || cidrs.isEmpty()) return false;
    byte[] addrBytes = resolveAddress(ip);
    if (addrBytes == null) return false;
    for (String cidr : cidrs) {
      if (inCidrBytes(addrBytes, cidr)) return true;
    }
    return false;
  }

  private byte[] resolveAddress(String ip) {
    try {
      return InetAddress.getByName(ip).getAddress();
    } catch (Exception e) {
      log.warn("Failed to resolve IP address {}: {}", ip, e.getMessage());
      return null;
    }
  }

  private boolean inCidrBytes(byte[] addrBytes, String cidr) {
    if (cidr == null) return false;
    Optional<ParsedCidr> opt = cidrCache.computeIfAbsent(cidr, this::parseCidr);
    if (opt.isEmpty()) return false;
    ParsedCidr parsed = opt.get();
    byte[] netBytes = parsed.networkBytes();
    int prefixLen = parsed.prefixLen();
    if (netBytes.length != addrBytes.length) return false;
    int fullBytes = prefixLen / 8;
    int remainingBits = prefixLen % 8;
    for (int i = 0; i < fullBytes; i++) {
      if (netBytes[i] != addrBytes[i]) return false;
    }
    if (remainingBits > 0 && fullBytes < netBytes.length) {
      int mask = 0xFF & (0xFF << (8 - remainingBits));
      if ((netBytes[fullBytes] & mask) != (addrBytes[fullBytes] & mask)) return false;
    }
    return true;
  }

  private Optional<ParsedCidr> parseCidr(String cidr) {
    try {
      String[] parts = cidr.split("/");
      if (parts.length != 2) return Optional.empty();
      byte[] networkBytes = InetAddress.getByName(parts[0].trim()).getAddress();
      int prefixLen = Integer.parseInt(parts[1].trim());
      int maxPrefix = networkBytes.length * 8;
      if (prefixLen < 0 || prefixLen > maxPrefix) {
        log.warn("CIDR prefix out of range for {}: {}", cidr, prefixLen);
        return Optional.empty();
      }
      return Optional.of(new ParsedCidr(networkBytes, prefixLen));
    } catch (Exception e) {
      log.warn("Failed to pre-parse CIDR {}: {}", cidr, e.getMessage());
      return Optional.empty();
    }
  }
}
