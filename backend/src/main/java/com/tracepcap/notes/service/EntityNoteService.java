package com.tracepcap.notes.service;

import com.tracepcap.notes.dto.EntityHistoryEntry;
import com.tracepcap.notes.dto.EntityNoteDto;
import com.tracepcap.notes.dto.UpsertNoteRequest;
import com.tracepcap.notes.entity.EntityNoteEntity;
import com.tracepcap.notes.repository.EntityNoteRepository;
import jakarta.transaction.Transactional;
import java.util.List;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EntityNoteService {

  private final EntityNoteRepository noteRepository;
  private final JdbcTemplate jdbc;

  // ── Notes CRUD ────────────────────────────────────────────────────────────

  public Optional<EntityNoteDto> getNote(String entityType, String entityKey) {
    return noteRepository
        .findByEntityTypeAndEntityKey(entityType, entityKey)
        .map(this::toDto);
  }

  @Transactional
  public EntityNoteDto upsert(UpsertNoteRequest req) {
    EntityNoteEntity entity =
        noteRepository
            .findByEntityTypeAndEntityKey(req.getEntityType(), req.getEntityKey())
            .orElseGet(
                () ->
                    EntityNoteEntity.builder()
                        .entityType(req.getEntityType())
                        .entityKey(req.getEntityKey())
                        .note("")
                        .build());
    entity.setNote(req.getNote());
    return toDto(noteRepository.save(entity));
  }

  @Transactional
  public void delete(String entityType, String entityKey) {
    noteRepository.deleteByEntityTypeAndEntityKey(entityType, entityKey);
  }

  // ── History ───────────────────────────────────────────────────────────────

  /**
   * Returns the list of files in which the given entity has appeared, ordered most-recent first.
   *
   * <p>For IP: any file containing a conversation where src_ip or dst_ip matches the key.
   * For DEVICE (MAC): any file whose host_classifications row has a matching mac.
   * For PROTOCOL: any file containing a conversation where protocol matches.
   * For APPLICATION: any file containing a conversation where app_name matches.
   */
  public List<EntityHistoryEntry> getHistory(String entityType, String entityKey) {
    return switch (entityType.toUpperCase()) {
      case "IP" -> historyForIp(entityKey);
      case "DEVICE" -> historyForDevice(entityKey);
      case "PROTOCOL" -> historyForProtocol(entityKey);
      case "APPLICATION" -> historyForApplication(entityKey);
      default -> List.of();
    };
  }

  private List<EntityHistoryEntry> historyForIp(String ip) {
    String sql =
        """
        SELECT f.id, f.file_name, f.start_time, f.end_time,
               f.packet_count, f.total_bytes
        FROM files f
        WHERE f.status = 'COMPLETED'
          AND EXISTS (
            SELECT 1 FROM conversations c
            WHERE c.file_id = f.id
              AND (c.src_ip = ? OR c.dst_ip = ?)
          )
        ORDER BY f.start_time DESC NULLS LAST
        LIMIT 100
        """;
    return jdbc.query(sql, (rs, i) -> EntityHistoryEntry.builder()
        .fileId(rs.getString("id"))
        .fileName(rs.getString("file_name"))
        .startTime(rs.getTimestamp("start_time") != null ? rs.getTimestamp("start_time").toLocalDateTime() : null)
        .endTime(rs.getTimestamp("end_time") != null ? rs.getTimestamp("end_time").toLocalDateTime() : null)
        .packetCount(rs.getObject("packet_count") != null ? rs.getLong("packet_count") : null)
        .totalBytes(rs.getObject("total_bytes") != null ? rs.getLong("total_bytes") : null)
        .build(), ip, ip);
  }

  private List<EntityHistoryEntry> historyForDevice(String mac) {
    String sql =
        """
        SELECT DISTINCT f.id, f.file_name, f.start_time, f.end_time,
               f.packet_count, f.total_bytes
        FROM files f
        JOIN host_classifications hc ON hc.file_id = f.id
        WHERE f.status = 'COMPLETED'
          AND LOWER(hc.mac) = LOWER(?)
        ORDER BY f.start_time DESC NULLS LAST
        LIMIT 100
        """;
    return jdbc.query(sql, (rs, i) -> EntityHistoryEntry.builder()
        .fileId(rs.getString("id"))
        .fileName(rs.getString("file_name"))
        .startTime(rs.getTimestamp("start_time") != null ? rs.getTimestamp("start_time").toLocalDateTime() : null)
        .endTime(rs.getTimestamp("end_time") != null ? rs.getTimestamp("end_time").toLocalDateTime() : null)
        .packetCount(rs.getObject("packet_count") != null ? rs.getLong("packet_count") : null)
        .totalBytes(rs.getObject("total_bytes") != null ? rs.getLong("total_bytes") : null)
        .build(), mac);
  }

  private List<EntityHistoryEntry> historyForProtocol(String protocol) {
    String sql =
        """
        SELECT DISTINCT f.id, f.file_name, f.start_time, f.end_time,
               f.packet_count, f.total_bytes
        FROM files f
        JOIN conversations c ON c.file_id = f.id
        WHERE f.status = 'COMPLETED'
          AND UPPER(c.tshark_protocol) = UPPER(?)
        ORDER BY f.start_time DESC NULLS LAST
        LIMIT 100
        """;
    return jdbc.query(sql, (rs, i) -> EntityHistoryEntry.builder()
        .fileId(rs.getString("id"))
        .fileName(rs.getString("file_name"))
        .startTime(rs.getTimestamp("start_time") != null ? rs.getTimestamp("start_time").toLocalDateTime() : null)
        .endTime(rs.getTimestamp("end_time") != null ? rs.getTimestamp("end_time").toLocalDateTime() : null)
        .packetCount(rs.getObject("packet_count") != null ? rs.getLong("packet_count") : null)
        .totalBytes(rs.getObject("total_bytes") != null ? rs.getLong("total_bytes") : null)
        .build(), protocol);
  }

  private List<EntityHistoryEntry> historyForApplication(String app) {
    String sql =
        """
        SELECT DISTINCT f.id, f.file_name, f.start_time, f.end_time,
               f.packet_count, f.total_bytes
        FROM files f
        JOIN conversations c ON c.file_id = f.id
        WHERE f.status = 'COMPLETED'
          AND UPPER(c.app_name) = UPPER(?)
        ORDER BY f.start_time DESC NULLS LAST
        LIMIT 100
        """;
    return jdbc.query(sql, (rs, i) -> EntityHistoryEntry.builder()
        .fileId(rs.getString("id"))
        .fileName(rs.getString("file_name"))
        .startTime(rs.getTimestamp("start_time") != null ? rs.getTimestamp("start_time").toLocalDateTime() : null)
        .endTime(rs.getTimestamp("end_time") != null ? rs.getTimestamp("end_time").toLocalDateTime() : null)
        .packetCount(rs.getObject("packet_count") != null ? rs.getLong("packet_count") : null)
        .totalBytes(rs.getObject("total_bytes") != null ? rs.getLong("total_bytes") : null)
        .build(), app);
  }

  // ── Mapper ────────────────────────────────────────────────────────────────

  private EntityNoteDto toDto(EntityNoteEntity e) {
    return EntityNoteDto.builder()
        .entityType(e.getEntityType())
        .entityKey(e.getEntityKey())
        .note(e.getNote())
        .createdAt(e.getCreatedAt())
        .updatedAt(e.getUpdatedAt())
        .build();
  }
}
