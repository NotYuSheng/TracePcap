package com.tracepcap.governance;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.LocalDateTime;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/** Someone who has signed in, and the client roles their last sign-in carried (V73). */
@Entity
@Table(name = "signed_in_users")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SignedInUserEntity {

  /** The token's subject: stable across a username change in Keycloak. */
  @Id private String subject;

  @Column(nullable = false)
  private String username;

  @Column(name = "display_name")
  private String displayName;

  @JdbcTypeCode(SqlTypes.ARRAY)
  @Column(name = "client_roles", nullable = false, columnDefinition = "text[]")
  private String[] clientRoles;

  @Column(name = "first_seen", nullable = false)
  private LocalDateTime firstSeen;

  @Column(name = "last_seen", nullable = false)
  private LocalDateTime lastSeen;
}
