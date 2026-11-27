package db.migration;

import com.tracepcap.common.net.Cidr;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Moves CIDRs saved before #1351 onto the form a save writes now ({@link Cidr#normalise}): host
 * bits zeroed ("10.1.2.3/24" → "10.1.2.0/24"), IPv6 in RFC 5952 form ("fd00:0:0:0:0:0:0:0/8" →
 * "fd00::/8"). Then every exact-text lookup and join (a network's override of a default, a
 * snapshot's label for a subnet) matches old rows and new ones alike.
 *
 * <p>Written in Java so it uses the same normaliser the services do, not a SQL copy of it.
 *
 * <p><b>Never fails the upgrade.</b> Rows are grouped by list (subnets by network and segment,
 * ranges and organisation rules by network, overrides by snapshot) and by the CIDR they normalise
 * to. A row is rewritten only when it's alone in its group, so no rewrite can meet a unique index.
 * A group of two or more (both spellings were saved) is left as it was and logged: which to keep
 * is the operator's call. A row that isn't a literal CIDR (free text an older validator let
 * through) is only trimmed. Snapshot overrides follow the same rule, so a subnet and its
 * per-snapshot labels move together.
 */
public class V86__normalise_saved_cidrs extends BaseJavaMigration {

  private static final Logger log = LoggerFactory.getLogger(V86__normalise_saved_cidrs.class);

  /** A table and the columns that make one list within it. */
  private record Table(String name, String scope) {}

  private static final List<Table> TABLES = List.of(
      new Table("subnet_definitions", "COALESCE(CAST(network_id AS text), '') || '|' || COALESCE(segment_key, '')"),
      new Table("custom_private_ranges", "COALESCE(CAST(network_id AS text), '')"),
      new Table("ip_org_rules", "COALESCE(CAST(network_id AS text), '')"),
      new Table("snapshot_subnet_overrides", "CAST(snapshot_id AS text)"));

  private record Row(long id, String cidr, String key) {}

  @Override
  public void migrate(Context context) throws Exception {
    Connection c = context.getConnection();
    for (Table t : TABLES) migrate(c, t);
  }

  private static void migrate(Connection c, Table t) throws Exception {
    Map<String, List<Row>> groups = new LinkedHashMap<>();
    try (Statement s = c.createStatement();
        ResultSet rs = s.executeQuery("SELECT id, cidr, " + t.scope() + " AS scope FROM " + t.name())) {
      while (rs.next()) {
        String cidr = rs.getString("cidr");
        if (cidr == null) continue;
        String key = Cidr.key(cidr);
        groups.computeIfAbsent(rs.getString("scope") + "\u0000" + key, k -> new ArrayList<>())
            .add(new Row(rs.getLong("id"), cidr, key));
      }
    }
    int rewritten = 0;
    try (PreparedStatement up = c.prepareStatement("UPDATE " + t.name() + " SET cidr = ? WHERE id = ?")) {
      for (List<Row> g : groups.values()) {
        if (g.size() > 1) {
          if (g.stream().anyMatch(r -> !r.cidr().equals(r.key()))) {
            log.warn("{}: rows {} all name {}; left as saved, keep one in settings", t.name(),
                g.stream().map(r -> r.id() + " (" + r.cidr() + ")").toList(), g.get(0).key());
          }
          continue;
        }
        Row r = g.get(0);
        if (r.cidr().equals(r.key())) continue;
        up.setString(1, r.key());
        up.setLong(2, r.id());
        up.addBatch();
        rewritten++;
      }
      if (rewritten > 0) up.executeBatch();
    }
    if (rewritten > 0) log.info("{}: {} CIDR(s) rewritten in the form a save writes", t.name(), rewritten);
  }
}
