package com.tracepcap.intelligence.service;

import com.tracepcap.intelligence.dto.CustomPrivateRangeDto;
import com.tracepcap.intelligence.entity.CustomPrivateRangeEntity;
import com.tracepcap.intelligence.repository.CustomPrivateRangeRepository;
import java.net.InetAddress;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomPrivateRangeService {

  private final CustomPrivateRangeRepository repository;

  private record ParsedCidr(byte[] networkBytes, int prefixLen) {}
  private static final ConcurrentHashMap<String, Optional<ParsedCidr>> cidrCache =
      new ConcurrentHashMap<>();

  public List<CustomPrivateRangeDto> list() {
    return repository.findAllByOrderByCreatedAtDesc().stream()
        .map(e -> CustomPrivateRangeDto.builder().id(e.getId()).cidr(e.getCidr()).label(e.getLabel()).build())
        .collect(Collectors.toList());
  }

  public CustomPrivateRangeDto create(CustomPrivateRangeDto dto) {
    String cidr = dto.getCidr().trim();
    // Normalise bare IP to /32 or /128
    if (!cidr.contains("/")) {
      try {
        InetAddress addr = InetAddress.getByName(cidr);
        cidr = cidr + (addr.getAddress().length == 4 ? "/32" : "/128");
      } catch (Exception e) {
        throw new IllegalArgumentException("Invalid IP address: " + cidr);
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
    } catch (IllegalArgumentException e) {
      throw e;
    } catch (Exception e) {
      throw new IllegalArgumentException("Invalid IP address in CIDR: " + cidr);
    }
    String label = dto.getLabel() != null && !dto.getLabel().isBlank() ? dto.getLabel().trim() : null;
    CustomPrivateRangeEntity entity = CustomPrivateRangeEntity.builder()
        .cidr(cidr)
        .label(label)
        .createdAt(LocalDateTime.now())
        .build();
    entity = repository.save(entity);
    return CustomPrivateRangeDto.builder().id(entity.getId()).cidr(entity.getCidr()).label(entity.getLabel()).build();
  }

  public void delete(Long id) {
    repository.deleteById(id);
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
    for (CustomPrivateRangeEntity range : ranges) {
      if (inCidr(ip, range.getCidr())) return true;
    }
    return false;
  }

  private boolean inCidr(String ip, String cidr) {
    if (ip == null || cidr == null) return false;
    try {
      Optional<ParsedCidr> opt = cidrCache.computeIfAbsent(cidr, this::parseCidr);
      if (opt.isEmpty()) return false;
      ParsedCidr parsed = opt.get();
      byte[] addrBytes = InetAddress.getByName(ip).getAddress();
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
    } catch (Exception e) {
      log.warn("CIDR match error ip={} cidr={}: {}", ip, cidr, e.getMessage());
      return false;
    }
  }

  private Optional<ParsedCidr> parseCidr(String cidr) {
    try {
      String[] parts = cidr.split("/");
      if (parts.length != 2) return Optional.empty();
      byte[] networkBytes = InetAddress.getByName(parts[0].trim()).getAddress();
      int prefixLen = Integer.parseInt(parts[1].trim());
      return Optional.of(new ParsedCidr(networkBytes, prefixLen));
    } catch (Exception e) {
      log.warn("Failed to pre-parse CIDR {}: {}", cidr, e.getMessage());
      return Optional.empty();
    }
  }
}
