package db.migration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracepcap.common.exception.FieldValidationException;
import com.tracepcap.signatures.dto.DetectionRuleRequest;
import com.tracepcap.signatures.service.RuleCodec;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Imports the old mounted {@code signatures.yml} into {@code detection_rules}, once (#925 phase
 * 1). Flyway records it, so it never runs again; later changes go through the app.
 *
 * <p>Never fails the upgrade over the file's content. A missing or unreadable file imports
 * nothing. A rule the editor would reject (a regex that doesn't compile, a rule with no criteria)
 * is still imported, but <b>disabled</b>, with the problem in its description, so nothing is lost
 * and nothing starts matching differently. A rule without a name, or a repeat of a name already
 * imported, is skipped, as the old matcher skipped it. One audit entry records the import.
 *
 * <p>The path is the Flyway placeholder {@code legacySignaturesPath} (application.yml), which is
 * where the old {@code config_data} volume put the file.
 */
public class V51__import_signatures_yml extends BaseJavaMigration {

  private static final Logger log = LoggerFactory.getLogger(V51__import_signatures_yml.class);
  static final String ACTOR = "system";

  @Override
  public void migrate(Context context) throws Exception {
    String path = context.getConfiguration().getPlaceholders().get("legacySignaturesPath");
    if (path == null || path.isBlank()) return;
    importFile(context.getConnection(), Path.of(path));
  }

  /** What the import did. Public for the integration test. */
  public record Result(int imported, List<String> disabled, List<String> skipped) {}

  public static Result importFile(Connection conn, Path file) throws Exception {
    if (!Files.isReadable(file)) {
      log.info("No signatures.yml at {}; no detection rules to import", file);
      return new Result(0, List.of(), List.of());
    }
    List<RuleCodec.ParsedRule> parsed;
    try {
      parsed = RuleCodec.parseYaml(Files.readString(file, StandardCharsets.UTF_8));
    } catch (FieldValidationException e) {
      // The old matcher also ignored a file it couldn't parse: nothing was matching from it.
      log.warn("signatures.yml at {} is not a valid rules file ({}); nothing imported", file, e.getErrors());
      return new Result(0, List.of(), List.of("(the whole file: " + e.getErrors().values() + ")"));
    }

    ObjectMapper json = new ObjectMapper();
    Timestamp now = Timestamp.valueOf(LocalDateTime.now());
    Set<String> names = new HashSet<>();
    List<String> imported = new ArrayList<>();
    List<String> disabled = new ArrayList<>();
    List<String> skipped = new ArrayList<>();
    String sql =
        "INSERT INTO detection_rules (id, scope, name, description, severity, enabled, match_criteria,"
            + " payload_contains, payload_regex, match_all, device_type, version, created_at, created_by,"
            + " updated_at, updated_by) VALUES (?, 'GLOBAL', ?, ?, ?, ?, ?::jsonb, ?::jsonb, ?::jsonb, ?, ?, 1,"
            + " ?, ?, ?, ?)";
    try (PreparedStatement ps = conn.prepareStatement(sql)) {
      for (RuleCodec.ParsedRule p : parsed) {
        DetectionRuleRequest r = p.rule();
        String name = r.getName() == null ? null : r.getName().trim();
        if (name == null || name.isEmpty()) {
          skipped.add("(a rule without a name)");
          continue;
        }
        if (name.length() > 200 || !names.add(name.toLowerCase(Locale.ROOT))) {
          skipped.add(name);
          continue;
        }
        Map<String, String> errors = RuleCodec.validate(r);
        boolean enabled = r.isEnabled() && errors.isEmpty();
        String description = r.getDescription();
        if (!errors.isEmpty()) {
          disabled.add(name);
          String note = "[Imported disabled: " + String.join(" ", errors.values()) + "]";
          description = description == null ? note : description + "\n" + note;
        }
        String severity =
            Set.of("low", "medium", "high", "critical").contains(r.getSeverity()) ? r.getSeverity() : "low";
        ps.setObject(1, UUID.randomUUID());
        ps.setString(2, name);
        ps.setString(3, description);
        ps.setString(4, severity);
        ps.setBoolean(5, enabled);
        ps.setString(6, json.writeValueAsString(RuleCodec.toMatchMap(r.getMatch())));
        ps.setString(7, json.writeValueAsString(RuleCodec.toPayloadContains(r.getPayloadContains())));
        ps.setString(8, json.writeValueAsString(RuleCodec.toPayloadRegex(r.getPayloadRegex())));
        ps.setBoolean(9, r.isMatchAll());
        String deviceType = p.deviceType();
        ps.setString(10, deviceType != null && deviceType.length() > 100 ? deviceType.substring(0, 100) : deviceType);
        ps.setTimestamp(11, now);
        ps.setString(12, ACTOR);
        ps.setTimestamp(13, now);
        ps.setString(14, ACTOR);
        ps.addBatch();
        imported.add(name);
      }
      ps.executeBatch();
    }

    if (!imported.isEmpty() || !skipped.isEmpty()) {
      Map<String, Object> after = new LinkedHashMap<>();
      after.put("file", file.toString());
      after.put("imported", imported.size());
      after.put("importedDisabled", disabled);
      after.put("skipped", skipped);
      try (PreparedStatement ps =
          conn.prepareStatement(
              "INSERT INTO audit_log (at, actor, action, target_type, target_id, before_value, after_value)"
                  + " VALUES (?, ?, 'detection-rules.import', 'detection-rule', NULL, NULL, ?::jsonb)")) {
        ps.setTimestamp(1, now);
        ps.setString(2, ACTOR);
        ps.setString(3, json.writeValueAsString(after));
        ps.executeUpdate();
      }
    }
    log.info(
        "Imported {} detection rule(s) from {} ({} disabled as invalid, {} skipped)",
        imported.size(), file, disabled.size(), skipped.size());
    return new Result(imported.size(), disabled, skipped);
  }
}
