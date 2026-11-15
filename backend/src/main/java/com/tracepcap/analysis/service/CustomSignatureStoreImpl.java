package com.tracepcap.analysis.service;

import com.tracepcap.analysis.spi.CustomSignatureStore;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.BatchPreparedStatementSetter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/** Rewrites {@code conversations.custom_signatures} for one capture (#925 phase 2). */
@Service
@RequiredArgsConstructor
class CustomSignatureStoreImpl implements CustomSignatureStore {

  private final JdbcTemplate jdbc;

  @Override
  @Transactional(propagation = Propagation.MANDATORY)
  public void replaceForFile(UUID fileId, Map<UUID, List<String>> byConversation) {
    // Clear the conversations that no longer match anything (only those that had labels, so an
    // untouched capture costs one indexed scan and no writes)...
    jdbc.update(
        "UPDATE conversations SET custom_signatures = '{}' WHERE file_id = ?"
            + " AND custom_signatures IS NOT NULL AND cardinality(custom_signatures) > 0",
        fileId);
    if (byConversation.isEmpty()) return;
    // ...then set the ones that do.
    List<Map.Entry<UUID, List<String>>> rows = new ArrayList<>(byConversation.entrySet());
    jdbc.batchUpdate(
        "UPDATE conversations SET custom_signatures = ? WHERE id = ? AND file_id = ?",
        new BatchPreparedStatementSetter() {
          @Override
          public void setValues(PreparedStatement ps, int i) throws SQLException {
            var row = rows.get(i);
            ps.setArray(1, ps.getConnection().createArrayOf("text", row.getValue().toArray()));
            ps.setObject(2, row.getKey());
            ps.setObject(3, fileId);
          }

          @Override
          public int getBatchSize() {
            return rows.size();
          }
        });
  }
}
