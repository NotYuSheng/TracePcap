package db.migration;

import com.tracepcap.common.net.Cidr;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
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
 * is the operator's call. A network contested anywhere in a family (a subnet and its overrides, a
 * default and a network's override of it) is left as saved throughout it, so text joins still
 * match. A row that isn't a literal CIDR (free text an older validator let through) is only
 * trimmed. The services keep honouring a spelling sent back exactly as saved ({@code
 * Cidr.asSaved}), so a row left here can still be edited, hidden or carried.
 *
 * <p>It calls the live {@link Cidr}, as V51 calls RuleCodec: a later change to how Cidr writes a
 * CIDR changes what this writes on a database not yet at V86. Cidr's tests pin its output.
 */
public class V86__normalise_saved_cidrs extends BaseJavaMigration {

  private static final Logger log = LoggerFactory.getLogger(V86__normalise_saved_cidrs.class);

  /** A table and the columns that make one list within it. */
  private record Table(String name, String scope) {}

  /**
   * Tables whose rows are matched to each other by CIDR text: a subnet and its per-snapshot
   * overrides, a default and a network's override of it. A network that's contested anywhere in a
   * family is left as saved everywhere in it, so old and new spellings never mix for one range.
   */
  private static final List<List<Table>> FAMILIES = List.of(
      List.of(
          new Table("subnet_definitions", "COALESCE(CAST(network_id AS text), '') || '|' || COALESCE(segment_key, '')"),
          new Table("snapshot_subnet_overrides", "CAST(snapshot_id AS text)")),
      List.of(new Table("custom_private_ranges", "COALESCE(CAST(network_id AS text), '')")),
      List.of(new Table("ip_org_rules", "COALESCE(CAST(network_id AS text), '')")));

  private record Row(long id, String cidr, String key) {}

  @Override
  public void migrate(Context context) throws Exception {
    Connection c = context.getConnection();
    for (List<Table> family : FAMILIES) migrate(c, family);
  }

  private static void migrate(Connection c, List<Table> family) throws Exception {
    // Per table: its lists' rows, grouped by the CIDR they normalise to.
    Map<Table, Map<String, List<Row>>> byTable = new LinkedHashMap<>();
    Set<String> contested = new HashSet<>();
    for (Table t : family) {
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
      for (List<Row> g : groups.values()) {
        if (g.size() > 1) {
          contested.add(g.get(0).key());
          log.warn("{}: rows {} all name {}; left as saved, keep one in settings", t.name(),
              g.stream().map(r -> r.id() + " (" + r.cidr() + ")").toList(), g.get(0).key());
        }
      }
      byTable.put(t, groups);
    }
    for (var e : byTable.entrySet()) {
      Table t = e.getKey();
      int rewritten = 0;
      try (PreparedStatement up = c.prepareStatement("UPDATE " + t.name() + " SET cidr = ? WHERE id = ?")) {
        for (List<Row> g : e.getValue().values()) {
          Row r = g.get(0);
          if (g.size() > 1 || contested.contains(r.key()) || r.cidr().equals(r.key())) continue;
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
}
