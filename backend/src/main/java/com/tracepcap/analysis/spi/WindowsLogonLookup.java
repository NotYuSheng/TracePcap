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

  /**
   * Who was on a host at a given moment (#812 follow-up), answered only when it's unambiguous.
   *
   * @param username the one account, or null when there are several
   * @param accountCount how many accounts had logged in by then (at least 1)
   * @param firstLoginAt when that account was first seen logging in; null when there are several
   */
  record UserAtTime(String username, int accountCount, LocalDateTime firstLoginAt) {}

  /** Answers {@link UserAtTime} for any of a fixed set of hosts. */
  @FunctionalInterface
  interface AccountsAtTime {
    AccountsAtTime NONE = (ip, when) -> null;

    /** The account(s) logged in on {@code ip} at or before {@code when}; null if none. */
    UserAtTime at(String ip, LocalDateTime when);
  }

  /**
   * Loads the logins for these hosts once, for answering many rows (a page of conversations). Same
   * rule as the host label: Kerberos logins decide when there are any by then, otherwise LDAP
   * lookups in the default Users folder, never on server/router hosts, and never custom-folder
   * candidates. A capture records logins but rarely logouts, so this is "logged in by then", not
   * "still signed in".
   */
  AccountsAtTime accountsAtTime(UUID fileId, java.util.Collection<String> ips);
}
