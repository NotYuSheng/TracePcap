package com.tracepcap.intelligence.service;

import com.tracepcap.intelligence.dto.CustomPrivateRangeDto;
import com.tracepcap.intelligence.entity.CustomPrivateRangeEntity;
import com.tracepcap.intelligence.repository.CustomPrivateRangeRepository;
import java.net.InetAddress;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
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

  public static final String PRIVATE = "PRIVATE";
  public static final String PUBLIC = "PUBLIC";

  private record ParsedCidr(byte[] networkBytes, int prefixLen) {}
  private final ConcurrentHashMap<String, Optional<ParsedCidr>> cidrCache =
      new ConcurrentHashMap<>();

  // Matches dotted-decimal IPv4 or hex-colon IPv6 — rejects hostnames before DNS lookup
  private static final Pattern NUMERIC_IP =
      Pattern.compile("^(\\d{1,3}\\.){3}\\d{1,3}$|^[0-9a-fA-F]*:[0-9a-fA-F:.]*$");

  public List<CustomPrivateRangeDto> list() {
    return repository.findAllByOrderByCreatedAtDesc().stream()
        .map(CustomPrivateRangeService::toDto)
        .collect(Collectors.toList());
  }

  private static CustomPrivateRangeDto toDto(CustomPrivateRangeEntity e) {
    return CustomPrivateRangeDto.builder()
        .id(e.getId())
        .cidr(e.getCidr())
        .classification(e.getClassification())
        .build();
  }

  public CustomPrivateRangeDto create(CustomPrivateRangeDto dto) {
    String cidr = dto.getCidr().trim();
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
    String classification = normaliseClassification(dto.getClassification());
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
  private String normaliseClassification(String raw) {
    if (raw == null || raw.isBlank()) return PRIVATE;
    String upper = raw.trim().toUpperCase();
    if (!upper.equals(PRIVATE) && !upper.equals(PUBLIC)) {
      throw new IllegalArgumentException("Classification must be PRIVATE or PUBLIC");
    }
    return upper;
  }

  public void delete(Long id) {
    repository.deleteById(id);
    cidrCache.clear();
  }

  /** Loads all custom private ranges for use in batch classification. */
  public List<CustomPrivateRangeEntity> loadRanges() {
    return repository.findAllByOrderByCreatedAtDesc();
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
        return PUBLIC.equals(range.getClassification())
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
