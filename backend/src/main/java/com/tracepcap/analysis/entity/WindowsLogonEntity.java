package com.tracepcap.analysis.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.LocalDateTime;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * One Windows account seen on one host in one capture, with when (#812). Every account is kept,
 * not just the one picked for the host's label. See {@code WindowsIdentityResolverService.Logon}.
 */
@Entity
@Table(name = "windows_logons")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class WindowsLogonEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(name = "file_id", nullable = false)
  private UUID fileId;

  @Column(nullable = false, length = 45)
  private String ip;

  @Column(nullable = false, length = 255)
  private String username;

  /** kerberos_as_req (signed in) | ldap_dn (looked up). */
  @Column(nullable = false, length = 20)
  private String source;

  @Column(name = "directory_entry")
  private String directoryEntry;

  @Column(length = 255)
  private String folder;

  /** USERS | CUSTOM, for LDAP lookups. */
  @Column(name = "folder_kind", length = 10)
  private String folderKind;

  @Column(length = 255)
  private String domain;

  @Column(name = "first_seen")
  private LocalDateTime firstSeen;

  @Column(name = "last_seen")
  private LocalDateTime lastSeen;

  @Column(name = "seen_count", nullable = false)
  private int seenCount;
}
