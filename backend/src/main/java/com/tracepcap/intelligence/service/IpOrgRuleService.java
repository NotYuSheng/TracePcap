package com.tracepcap.intelligence.service;

import com.tracepcap.intelligence.dto.IpOrgRuleDto;
import com.tracepcap.intelligence.entity.IpOrgRuleEntity;
import com.tracepcap.intelligence.repository.IpOrgRuleRepository;
import java.net.InetAddress;
import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class IpOrgRuleService {

  private final IpOrgRuleRepository repository;

  public List<IpOrgRuleDto> list() {
    return repository.findAllByOrderByPrefixLengthDescLabelAsc().stream()
        .map(e -> IpOrgRuleDto.builder().id(e.getId()).label(e.getLabel()).cidr(e.getCidr()).build())
        .collect(Collectors.toList());
  }

  public IpOrgRuleDto create(IpOrgRuleDto dto) {
    String cidr = dto.getCidr().trim();
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
      String[] parts = cidr.split("/");
      if (parts.length != 2) return false;
      int prefixLen = Integer.parseInt(parts[1].trim());
      InetAddress network = InetAddress.getByName(parts[0].trim());
      InetAddress address = InetAddress.getByName(ip);
      byte[] netBytes = network.getAddress();
      byte[] addrBytes = address.getAddress();
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
}
