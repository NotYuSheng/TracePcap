package com.tracepcap.common.net;

import java.util.Set;

/**
 * The single answer to "is this an ordinary infrastructure service port".
 *
 * <p>Traffic to these ports is inherently regular — Windows session keepalives (NetBIOS, SMB),
 * directory and authentication lookups (Kerberos, LDAP), time sync, DNS, DHCP, remote admin — so
 * <em>regularity alone</em> says nothing about them. A beacon detector that flags periodicity to
 * these ports reports every domain-joined workstation talking to its domain controller (#823).
 *
 * <p>This is deliberately a list of <em>services</em>, not "well-known ports": a caller asking
 * "could this be an unexplained channel" wants this set, and a port outside it is not thereby
 * suspicious — only not excused.
 */
public final class ServicePorts {

  private ServicePorts() {}

  private static final Set<Integer> INFRASTRUCTURE =
      Set.of(
          20, 21, 22, 23, 25, // FTP, SSH, telnet, SMTP
          53, 67, 68, 123, // DNS, DHCP, NTP
          80, 443, 8080, 8443, // HTTP(S)
          88, 389, 636, 3268, 3269, // Kerberos, LDAP / LDAPS, global catalog
          110, 143, 465, 587, 993, 995, // mail
          135, 137, 138, 139, 445, // RPC endpoint mapper, NetBIOS, SMB
          161, 162, // SNMP
          1900, 5353, // SSDP, mDNS
          2049, // NFS
          3389, 5985, 5986); // RDP, WinRM

  /** Whether {@code port} is an ordinary infrastructure service port. Null (no port) is not. */
  public static boolean isInfrastructure(Integer port) {
    return port != null && INFRASTRUCTURE.contains(port);
  }
}
