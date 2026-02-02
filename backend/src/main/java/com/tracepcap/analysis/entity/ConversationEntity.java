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
@Table(name = "conversations")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ConversationEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID id;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "file_id", nullable = false)
  private FileEntity file;

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

  @Column(name = "packet_count", nullable = false)
  @Builder.Default
  private Long packetCount = 0L;

  @Column(name = "total_bytes", nullable = false)
  @Builder.Default
  private Long totalBytes = 0L;

  @Column(name = "start_time", nullable = false)
  private LocalDateTime startTime;

  @Column(name = "end_time", nullable = false)
  private LocalDateTime endTime;

  @CreationTimestamp
  @Column(name = "created_at", nullable = false, updatable = false)
  private LocalDateTime createdAt;
}
