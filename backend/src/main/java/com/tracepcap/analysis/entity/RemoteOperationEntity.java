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

/** One kind of SMB or RPC operation one host made on another, on a conversation (#1266). See V82. */
@Entity
@Table(name = "remote_operations")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RemoteOperationEntity {
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

  @Column(name = "server_ip", nullable = false)
  private String serverIp;

  @Column(nullable = false)
  private String kind;

  private String share;

  private String path;

  @Column(name = "interface_uuid")
  private String interfaceUuid;

  private Integer opnum;

  private Long bytes;

  private String status;

  @Column(name = "op_count", nullable = false)
  private int count;
}
