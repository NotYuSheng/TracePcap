package com.tracepcap.analysis.service;

import com.tracepcap.analysis.repository.WindowsLogonRepository;
import com.tracepcap.analysis.spi.WindowsLogonLookup;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@RequiredArgsConstructor
public class WindowsLogonLookupAdapter implements WindowsLogonLookup {

  private final WindowsLogonRepository repository;
  private final com.tracepcap.analysis.repository.HostClassificationRepository hostRepository;

  /** Same set as AnalysisService.NO_LDAP_SIGN_IN: hosts where an LDAP lookup isn't a sign-in. */
  private static final java.util.Set<String> NO_LDAP_SIGN_IN =
      java.util.Set.of("SERVER", "ROUTER", "DNS_SERVER", "WEB_SERVER", "API_SERVER");

  @Override
  @Transactional(readOnly = true)
  public AccountsAtTime accountsAtTime(UUID fileId, java.util.Collection<String> ips) {
    if (ips.isEmpty()) return AccountsAtTime.NONE;
    java.util.Map<String, List<com.tracepcap.analysis.entity.WindowsLogonEntity>> byIp =
        repository.findByFileIdAndIpIn(fileId, ips).stream()
            .filter(e -> !"CUSTOM".equals(e.getFolderKind()) && e.getFirstSeen() != null)
            .collect(java.util.stream.Collectors.groupingBy(e -> e.getIp()));
    if (byIp.isEmpty()) return AccountsAtTime.NONE;
    java.util.Set<String> ldapIgnored =
        hostRepository.findByFileIdAndIpIn(fileId, byIp.keySet()).stream()
            .filter(h -> NO_LDAP_SIGN_IN.contains(h.getDeviceType()))
            .map(h -> h.getIp())
            .collect(java.util.stream.Collectors.toSet());

    return (ip, when) -> {
      if (ip == null || when == null) return null;
      List<com.tracepcap.analysis.entity.WindowsLogonEntity> logons = byIp.get(ip);
      if (logons == null) return null;
      java.util.Map<String, java.time.LocalDateTime> kerberos = firstLogins(logons, when, "kerberos_as_req");
      java.util.Map<String, java.time.LocalDateTime> accounts =
          !kerberos.isEmpty() || ldapIgnored.contains(ip)
              ? kerberos
              : firstLogins(logons, when, "ldap_dn");
      if (accounts.isEmpty()) return null;
      if (accounts.size() > 1) return new UserAtTime(null, accounts.size(), null);
      var only = accounts.entrySet().iterator().next();
      return new UserAtTime(only.getKey(), 1, only.getValue());
    };
  }

  /** Accounts from {@code source} first seen at or before {@code when}, each with its first login. */
  private static java.util.Map<String, java.time.LocalDateTime> firstLogins(
      List<com.tracepcap.analysis.entity.WindowsLogonEntity> logons,
      java.time.LocalDateTime when,
      String source) {
    java.util.Map<String, java.time.LocalDateTime> out = new java.util.HashMap<>();
    for (var e : logons) {
      if (source.equals(e.getSource()) && !e.getFirstSeen().isAfter(when)) {
        out.merge(e.getUsername(), e.getFirstSeen(), (a, b) -> a.isBefore(b) ? a : b);
      }
    }
    return out;
  }

  @Override
  @Transactional(readOnly = true)
  public List<WindowsLogon> logonsFor(UUID fileId, String ip) {
    return repository.findByFileIdAndIpOrderByFirstSeenAscIdAsc(fileId, ip).stream()
        .map(
            e ->
                new WindowsLogon(
                    e.getUsername(),
                    e.getSource(),
                    e.getDirectoryEntry(),
                    e.getFolder(),
                    e.getFolderKind(),
                    e.getDomain(),
                    e.getFirstSeen(),
                    e.getLastSeen(),
                    e.getSeenCount(),
                    "CUSTOM".equals(e.getFolderKind())))
        .toList();
  }
}
