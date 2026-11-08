package com.tracepcap.policy.service;

import com.tracepcap.policy.dto.IpOrgRuleDto;
import com.tracepcap.policy.entity.IpOrgRuleEntity;
import com.tracepcap.policy.repository.IpOrgRuleRepository;
import java.net.InetAddress;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
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
  private final com.tracepcap.governance.PermissionService permissionService;
  private final com.tracepcap.governance.AuditLogService auditLog;

  /** Pre-parsed CIDR cache: avoids repeated string splitting and InetAddress construction. */
  private record ParsedCidr(byte[] networkBytes, int prefixLen) {}
  private static final ConcurrentHashMap<String, Optional<ParsedCidr>> cidrCache =
      new ConcurrentHashMap<>();

  /** The shared default. */
  public List<IpOrgRuleDto> list() {
    return repository.findByNetworkIdIsNullOrderByPrefixLengthDescLabelAsc().stream()
        .map(e -> IpOrgRuleDto.builder().id(e.getId()).label(e.getLabel()).cidr(e.getCidr()).build())
        .collect(Collectors.toList());
  }

  /** Validates a CIDR (an address and a prefix length). */
  private static String validCidr(String raw) {
    if (raw == null || raw.isBlank()) throw new IllegalArgumentException("A CIDR is required");
    String cidr = raw.trim();
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
    return cidr;
  }

  /** Adds a rule to the shared default. */
  public IpOrgRuleDto create(IpOrgRuleDto dto) {
    String cidr = validCidr(dto.getCidr());
    if (dto.getLabel() == null || dto.getLabel().isBlank()) throw new IllegalArgumentException("A label is required");
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

  /** Deletes a rule of the shared default. A network's entries are removed through the network. */
  public void delete(Long id) {
    repository.findById(id).filter(e -> e.getNetworkId() == null).ifPresent(repository::delete);
  }

  /** The shared default, most specific first. Call once and pass the result to matchIp. */
  public List<IpOrgRuleEntity> loadRules() {
    return repository.findByNetworkIdIsNullOrderByPrefixLengthDescLabelAsc();
  }

  /**
   * The rules in effect for a network (#915 phase 4), most specific first: its own entries layered
   * on the default, per CIDR. Null means the default.
   */
  public List<IpOrgRuleEntity> loadRules(UUID networkId) {
    if (networkId == null) return loadRules();
    List<IpOrgRuleEntity> out =
        new java.util.ArrayList<>(
            com.tracepcap.common.net.NetworkLayering.effective(
                loadRules(),
                repository.findByNetworkIdOrderByPrefixLengthDescLabelAsc(networkId),
                IpOrgRuleEntity::getCidr,
                IpOrgRuleEntity::isHidden));
    // matchIp takes the first match, so keep most-specific-first across both layers. The sort is
    // stable, so for equal prefixes the network's entry stays ahead of the default's.
    out.sort(java.util.Comparator.comparingInt(IpOrgRuleEntity::getPrefixLength).reversed());
    return out;
  }

  // ── A network's entries (#915 phase 4) ──────────────────────────────────────

  /** A network's view: its own entries (hidden ones included), then the default's it leaves alone. */
  public List<IpOrgRuleDto> listForNetwork(UUID networkId) {
    List<IpOrgRuleEntity> defaults = loadRules();
    java.util.Set<String> defaultCidrs = defaults.stream().map(IpOrgRuleEntity::getCidr).collect(Collectors.toSet());
    List<IpOrgRuleEntity> own = repository.findByNetworkIdOrderByPrefixLengthDescLabelAsc(networkId);
    java.util.Set<String> ownCidrs = own.stream().map(IpOrgRuleEntity::getCidr).collect(Collectors.toSet());
    List<IpOrgRuleDto> out = new java.util.ArrayList<>();
    for (var e : own) {
      IpOrgRuleDto d = toDto(e);
      d.setScope("network");
      d.setHidden(e.isHidden());
      d.setOverridesDefault(defaultCidrs.contains(e.getCidr()));
      out.add(d);
    }
    for (var e : defaults) {
      if (ownCidrs.contains(e.getCidr())) continue;
      IpOrgRuleDto d = toDto(e);
      d.setScope("default");
      out.add(d);
    }
    return out;
  }

  /**
   * Sets the network's rule for a CIDR (override or addition), or hides the default's with {@code
   * hidden}. Needs NETWORK_SETTINGS; audited.
   */
  @org.springframework.transaction.annotation.Transactional
  public IpOrgRuleDto putForNetwork(UUID networkId, IpOrgRuleDto dto, boolean hidden) {
    permissionService.require(com.tracepcap.governance.PermissionAction.NETWORK_SETTINGS);
    String cidr = validCidr(dto.getCidr());
    String label;
    if (hidden) {
      label =
          loadRules().stream()
              .filter(e -> e.getCidr().equals(cidr))
              .map(IpOrgRuleEntity::getLabel)
              .findFirst()
              .orElseThrow(() -> new IllegalArgumentException("The default has no rule for " + cidr + " to hide."));
    } else {
      if (dto.getLabel() == null || dto.getLabel().isBlank()) throw new IllegalArgumentException("A label is required");
      label = dto.getLabel().trim();
    }
    IpOrgRuleEntity e =
        repository
            .findByNetworkIdAndCidr(networkId, cidr)
            .orElseGet(() -> IpOrgRuleEntity.builder().networkId(networkId).cidr(cidr).build());
    IpOrgRuleDto before = e.getId() == null ? null : toDto(e);
    e.setLabel(label);
    e.setPrefixLength(parsePrefixLength(cidr));
    e.setHidden(hidden);
    e.setCreatedAt(LocalDateTime.now());
    e = repository.save(e);
    IpOrgRuleDto after = toDto(e);
    after.setScope("network");
    after.setHidden(hidden);
    auditLog.record(
        hidden ? "ip-org-rule.network.hide" : "ip-org-rule.network.set",
        "network-ip-org-rule", networkId + "/" + cidr, before, after);
    return after;
  }

  /** Removes the network's rule, so the default applies again. Needs NETWORK_SETTINGS; audited. */
  @org.springframework.transaction.annotation.Transactional
  public void deleteForNetwork(UUID networkId, Long id) {
    permissionService.require(com.tracepcap.governance.PermissionAction.NETWORK_SETTINGS);
    IpOrgRuleEntity e =
        repository
            .findById(id)
            .filter(r -> networkId.equals(r.getNetworkId()))
            .orElseThrow(() -> new com.tracepcap.common.exception.ResourceNotFoundException("Entry not found: " + id));
    repository.delete(e);
    auditLog.record("ip-org-rule.network.revert", "network-ip-org-rule", networkId + "/" + e.getCidr(), toDto(e), null);
  }

  private static IpOrgRuleDto toDto(IpOrgRuleEntity e) {
    return IpOrgRuleDto.builder().id(e.getId()).label(e.getLabel()).cidr(e.getCidr()).build();
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
    return repository.countByNetworkIdIsNull() > 0;
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
