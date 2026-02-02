package com.tracepcap.analysis.entity;

import com.tracepcap.file.entity.FileEntity;
import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

@Entity
@Table(name = "packets")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PacketEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID id;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "file_id", nullable = false)
  private FileEntity file;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "conversation_id")
  private ConversationEntity conversation;

  @Column(name = "packet_number", nullable = false)
  private Long packetNumber;

  @Column(nullable = false)
  private LocalDateTime timestamp;

  @Column(name = "src_ip", nullable = false, length = 45)
  private String srcIp;

  @Column(name = "src_port")
  private Integer srcPort;

  @Column(name = "dst_ip", nullable = false, length = 45)
  private String dstIp;

  @Column(name = "dst_port")
  private Integer dstPort;

  @Column(nullable = false, length = 20)
  private String protocol;

  @Column(name = "packet_size", nullable = false)
  private Integer packetSize;

  @Column(columnDefinition = "TEXT")
  private String info;

  @CreationTimestamp
  @Column(name = "created_at", nullable = false, updatable = false)
  private LocalDateTime createdAt;
}
