package com.tracepcap.insights.service;

import com.tracepcap.analysis.spi.DeviceKeys;
import com.tracepcap.common.event.HostOccupanciesChangedEvent;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * Keeps labels on the right device when an address's devices change (#918 slice 3).
 *
 * <p>A label, role or piece of analyst evidence on a later device is keyed {@code ip@<start>}. A
 * split never moves one: the label stays with the part that contains its start.
 *
 * <ul>
 *   <li><b>A device goes away</b> (a merge, or undoing a split): its labels move to the device that
 *       now covers that time, and each move is recorded. If that device already has its own label
 *       for the same question, the moved one is left where it is, and comes back with the device.
 *   <li><b>A device comes back</b> (undoing the merge): the labels moved off it go back, as long as
 *       nothing has taken their place.
 * </ul>
 *
 * <p>Runs inside the decision's transaction, before the adjudicators re-answer after commit.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class DeviceLabelRekeyer {

  /** A label table: how to find, move and conflict-check one kind of label. */
  private record Kind(String name, String table, String questionColumn, String extraWhere) {}

  private static final List<Kind> KINDS =
      List.of(
          new Kind("override", "human_overrides", "question", ""),
          new Kind("evidence", "manual_evidence", "question", ""),
          new Kind("role", "node_roles", null, " AND entity_type = 'IP'"));

  private final JdbcTemplate jdbc;

  @EventListener
  public void onOccupanciesChanged(HostOccupanciesChangedEvent event) {
    restoreReturned(event.fileId(), event.ip(), event.starts());
    moveOrphans(event.fileId(), event.ip(), event.starts());
  }

  /** Labels on a device whose start is gone move to the device that now covers that time. */
  private void moveOrphans(UUID fileId, String ip, List<LocalDateTime> starts) {
    for (Kind k : KINDS) {
      String q = k.questionColumn() == null ? "NULL" : k.questionColumn();
      List<Map<String, Object>> rows =
          jdbc.queryForList(
              "SELECT id, entity_key, " + q + " AS question FROM " + k.table()
                  + " WHERE file_id = ? AND entity_key LIKE ?" + k.extraWhere(),
              fileId, ip + "@%");
      for (Map<String, Object> row : rows) {
        String key = (String) row.get("entity_key");
        if (!ip.equals(DeviceKeys.ipOf(key))) continue;
        LocalDateTime start = DeviceKeys.startOf(key);
        if (start == null || starts.contains(start)) continue; // still a device
        String target = DeviceKeys.key(ip, covering(starts, start));
        String question = (String) row.get("question");
        // Evidence has no one-per-key rule; overrides and roles do, and the target's own wins.
        if (!"evidence".equals(k.name()) && taken(k, fileId, target, question)) continue;
        long id = ((Number) row.get("id")).longValue();
        jdbc.update("UPDATE " + k.table() + " SET entity_key = ? WHERE id = ?", target, id);
        jdbc.update(
            "INSERT INTO device_label_moves (file_id, kind, question, row_id, from_key, to_key) VALUES (?, ?, ?, ?, ?, ?)",
            fileId, k.name(), question, id, key, target);
        log.info("Moved {} {} on {} to {} in file {}", k.name(), id, key, target, fileId);
      }
    }
  }

  /** Labels moved off a device that is back go back to it, unless something has taken its place. */
  private void restoreReturned(UUID fileId, String ip, List<LocalDateTime> starts) {
    List<Map<String, Object>> moves =
        jdbc.queryForList(
            "SELECT id, kind, question, row_id, from_key, to_key FROM device_label_moves"
                + " WHERE file_id = ? AND from_key LIKE ? ORDER BY id DESC",
            fileId, ip + "@%");
    for (Map<String, Object> m : moves) {
      String from = (String) m.get("from_key");
      LocalDateTime start = DeviceKeys.startOf(from);
      if (start == null || !starts.contains(start)) continue; // that device is still gone
      Kind k = KINDS.stream().filter(x -> x.name().equals(m.get("kind"))).findFirst().orElse(null);
      long moveId = ((Number) m.get("id")).longValue();
      if (k != null) {
        String question = (String) m.get("question");
        long rowId = ((Number) m.get("row_id")).longValue();
        boolean free = "evidence".equals(k.name()) || !taken(k, fileId, from, question);
        if (free) {
          int n =
              jdbc.update(
                  "UPDATE " + k.table() + " SET entity_key = ? WHERE id = ? AND entity_key = ?",
                  from, rowId, m.get("to_key"));
          if (n > 0) log.info("Moved {} {} back to {} in file {}", k.name(), rowId, from, fileId);
        }
      }
      jdbc.update("DELETE FROM device_label_moves WHERE id = ?", moveId);
    }
  }

  /** Whether {@code key} already has a label of this kind (for {@code question}, if it has one). */
  private boolean taken(Kind k, UUID fileId, String key, String question) {
    String sql = "SELECT count(*) FROM " + k.table() + " WHERE file_id = ? AND entity_key = ?" + k.extraWhere();
    Integer n =
        k.questionColumn() == null
            ? jdbc.queryForObject(sql, Integer.class, fileId, key)
            : jdbc.queryForObject(sql + " AND " + k.questionColumn() + " = ?", Integer.class, fileId, key, question);
    return n != null && n > 0;
  }

  /** The start of the device covering {@code t}: the latest start at or before it (null = the first). */
  static LocalDateTime covering(List<LocalDateTime> starts, LocalDateTime t) {
    LocalDateTime best = null;
    for (LocalDateTime s : starts) {
      if (s != null && !s.isAfter(t) && (best == null || s.isAfter(best))) best = s;
    }
    return best;
  }
}
