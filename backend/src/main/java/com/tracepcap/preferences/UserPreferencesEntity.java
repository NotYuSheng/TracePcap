package com.tracepcap.preferences;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.LocalDateTime;
import java.util.Map;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/** One profile's personal preferences (#915 phase 2). See V47. */
@Entity
@Table(name = "user_preferences")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserPreferencesEntity {

  @Id
  @Column(name = "profile_key", length = 255)
  private String profileKey;

  @JdbcTypeCode(SqlTypes.JSON)
  @Column(name = "preferences", columnDefinition = "jsonb", nullable = false)
  private Map<String, Object> preferences;

  @Column(name = "updated_at", nullable = false)
  private LocalDateTime updatedAt;
}
