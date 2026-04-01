package com.tracepcap.analysis.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.UpdateTimestamp;

@Entity
@Table(name = "ip_geo_cache")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IpGeoInfoEntity {

  /** The IP address is the primary key — one row per unique IP, shared across all files. */
  @Id
  @Column(length = 45)
  private String ip;

  @Column(length = 100)
  private String country;

  @Column(name = "country_code", length = 2)
  private String countryCode;

  /** ASN string, e.g. "AS15169". */
  @Column(length = 20)
  private String asn;

  /** Organisation name as returned by the lookup provider. */
  @Column(length = 255)
  private String org;

  @UpdateTimestamp
  @Column(name = "looked_up_at", nullable = false)
  private LocalDateTime lookedUpAt;
}
