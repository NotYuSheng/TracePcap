package com.tracepcap.analysis.spi;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

/** Read port for the Windows logins seen on a host (#812). */
public interface WindowsLogonLookup {

  /**
   * One account seen on one host.
   *
   * @param evidence {@code kerberos_as_req} (signed in) or {@code ldap_dn} (looked up)
   * @param folderKind {@code USERS} (Windows' default Users folder, normally people) or {@code
   *     CUSTOM} (an organisation-made folder: could be a person, a computer or a group); null for
   *     Kerberos
   * @param candidateOnly true for custom-folder lookups: shown to the analyst, never used by default
   */
  record WindowsLogon(
      String username,
      String evidence,
      String directoryEntry,
      String folder,
      String folderKind,
      String domain,
      LocalDateTime firstSeen,
      LocalDateTime lastSeen,
      int seenCount,
      boolean candidateOnly) {}

  /** The host's logins, oldest first. Empty when none were seen. */
  List<WindowsLogon> logonsFor(UUID fileId, String ip);
}
