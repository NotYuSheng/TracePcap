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
 * One Windows-identity claim for one IP in one capture — a REPORTED/MEASURED-grade observation
 * from Kerberos AS-REQ or an LDAP searchRequest DN (#809). All claims are kept; winner-picking
 * happens at adjudication, never at write time — same discipline as {@link HostnameClaimEntity}.
 */
@Entity
@Table(name = "windows_identity_claims")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class WindowsIdentityClaimEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(name = "file_id", nullable = false)
  private UUID fileId;

  @Column(nullable = false, length = 45)
  private String ip;

  @Column(nullable = false, length = 255)
  private String username;

  /** Which signal asserted it: kerberos_as_req | ldap_dn. */
  @Column(nullable = false, length = 20)
  private String source;

  @Column(name = "created_at", nullable = false, insertable = false, updatable = false)
  private LocalDateTime createdAt;
}
