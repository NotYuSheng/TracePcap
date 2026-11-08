package com.tracepcap.hostclassification.dto;

import java.time.LocalDateTime;
import lombok.Builder;
import lombok.Value;

/** One Windows account seen on a host, for the host's login timeline (#812). */
@Value
@Builder
public class WindowsLogonResponse {
  String username;
  /** {@code kerberos_as_req}: signed in. {@code ldap_dn}: looked up in the directory. */
  String evidence;
  /** LDAP only: the full directory entry, e.g. {@code CN=Clark Collier,CN=Users,DC=example,DC=com}. */
  String directoryEntry;
  /** LDAP only: the folder in plain words, e.g. {@code Users} or {@code Staff / Sales}. */
  String folder;
  /** LDAP only: {@code USERS} (Windows' default folder, normally people) or {@code CUSTOM}. */
  String folderKind;
  /** LDAP only: the domain, e.g. {@code example.com}. */
  String domain;
  LocalDateTime firstSeen;
  LocalDateTime lastSeen;
  int seenCount;
  /** A custom-folder lookup: could be a person, a computer or a group. Never used as the default label. */
  boolean candidateOnly;
}
