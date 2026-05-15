package com.lanturn.intelligence.service;

import com.lanturn.intelligence.dto.IpOrgRuleDto;
import com.lanturn.intelligence.entity.IpOrgRuleEntity;
import com.lanturn.intelligence.repository.IpOrgRuleRepository;
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
public class IpOrgRuleService {

  private final IpOrgRuleRepository repository;

  /** Pre-parsed CIDR cache: avoids repeated string splitting and InetAddress construction. */
  private record ParsedCidr(byte[] networkBytes, int prefixLen) {}
  private static final ConcurrentHashMap<String, Optional<ParsedCidr>> cidrCache =
      new ConcurrentHashMap<>();

  public List<IpOrgRuleDto> list() {
    return repository.findAllByOrderByPrefixLengthDescLabelAsc().stream()
        .map(e -> IpOrgRuleDto.builder().id(e.getId()).label(e.getLabel()).cidr(e.getCidr()).build())
        .collect(Collectors.toList());
  }

  public IpOrgRuleDto create(IpOrgRuleDto dto) {
    String cidr = dto.getCidr().trim();
    // Validate IP and prefix before persisting
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
    int prefixLength = parsePrefixLength(cidr);
    IpOrgRuleEntity entity = IpOrgRuleEntity.builder()
        .label(dto.getLabel().trim())
        .cidr(cidr)
        .prefixLength(prefixLength)
        .createdAt(LocalDateTime.now())
        .build();
    entity = repository.save(entity);
    return IpOrgRuleDto.builder().id(entity.getId()).label(entity.getLabel()).cidr(entity.getCidr()).build();
  }

  public void delete(Long id) {
    repository.deleteById(id);
  }

  /** Returns all rules sorted most-specific first. Call once and pass the result to matchIp. */
  public List<IpOrgRuleEntity> loadRules() {
    return repository.findAllByOrderByPrefixLengthDescLabelAsc();
  }

  /**
   * Returns the label of the first rule (most specific prefix) that contains the IP,
   * or null if none match.
   */
  public String matchIp(String ip, List<IpOrgRuleEntity> rules) {
    for (IpOrgRuleEntity rule : rules) {
      if (inCidr(ip, rule.getCidr())) {
        return rule.getLabel();
      }
    }
    return null;
  }

  public boolean hasRules() {
    return repository.count() > 0;
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  private int parsePrefixLength(String cidr) {
    try {
      String[] parts = cidr.split("/");
      if (parts.length == 2) return Integer.parseInt(parts[1].trim());
    } catch (NumberFormatException ignored) {
    }
    throw new IllegalArgumentException("Invalid CIDR: " + cidr);
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

  /** Pre-parses a CIDR string into network bytes + prefix length, cached by the caller. */
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
