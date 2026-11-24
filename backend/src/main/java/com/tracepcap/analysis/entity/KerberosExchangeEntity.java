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

/** One kind of Kerberos reply a KDC returned on a conversation (#1267). See V83. */
@Entity
@Table(name = "kerberos_exchanges")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class KerberosExchangeEntity {
  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID id;

  @Column(name = "file_id", nullable = false)
  private UUID fileId;

  @Column(name = "conversation_id", nullable = false)
  private UUID conversationId;

  @Column(name = "first_time")
  private LocalDateTime firstTime;

  @Column(name = "client_ip", nullable = false)
  private String clientIp;

  @Column(name = "kdc_ip", nullable = false)
  private String kdcIp;

  @Column(name = "msg_type", nullable = false)
  private String msgType;

  private String account;

  private String service;

  private String realm;

  @Column(name = "error_code")
  private String errorCode;

  private String encryption;

  @Column(nullable = false)
  private boolean weak;

  @Column(name = "op_count", nullable = false)
  private int count;
}
