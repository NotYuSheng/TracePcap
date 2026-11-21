package com.tracepcap.governance;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Table;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * A role: a set of permissions (V72). Its key is the Keycloak client role that gives it; who has it
 * is decided in Keycloak, never here. The admin role's stored set is empty: it always has every
 * permission.
 */
@Entity
@Table(name = "roles")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RoleEntity {

  @Id
  @Column(name = "role_key", length = 100)
  private String key;

  @Column(nullable = false, length = 200)
  private String label;

  private String description;

  @Column(name = "built_in", nullable = false)
  private boolean builtIn;

  @Column(nullable = false)
  private int position;

  @Column(name = "is_default", nullable = false)
  private boolean defaultRole;

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "role_permissions", joinColumns = @JoinColumn(name = "role_key"))
  @Column(name = "action", length = 100)
  @Builder.Default
  private Set<String> permissions = new HashSet<>();

  @Column(name = "updated_at", nullable = false)
  private LocalDateTime updatedAt;

  @Column(name = "updated_by", nullable = false)
  private String updatedBy;
}
