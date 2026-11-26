package com.tracepcap.analysis.service;

import com.tracepcap.analysis.spi.IdsRuleMetadata;
import java.io.BufferedReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Reads the active Suricata ruleset's {@code sid} and {@code metadata} once, and again only when the
 * rules file changes (a newly imported ruleset). About 53,000 rules take well under a second.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SuricataRuleMetadataIndex implements IdsRuleMetadata {

  private static final Pattern SID = Pattern.compile("\\bsid\\s*:\\s*(\\d+)\\s*;");
  private static final Pattern METADATA = Pattern.compile("\\bmetadata\\s*:([^;]*);");
  private static final Pattern FAMILY = Pattern.compile("\\bmalware_family\\s+([^,;]+)");

  private final SuricataRuleset ruleset;

  private record Loaded(Path file, long modified, Map<Long, RuleInfo> rules) {}

  private volatile Loaded loaded;

  @Override
  public Optional<RuleInfo> rule(long sid) {
    Map<Long, RuleInfo> rules = rules();
    return Optional.ofNullable(rules.get(sid));
  }

  private Map<Long, RuleInfo> rules() {
    Path file;
    try {
      file = ruleset.active().rulesFile();
    } catch (Exception e) {
      return Map.of();
    }
    if (file == null || !Files.isReadable(file)) return Map.of();
    long modified;
    try {
      modified = Files.getLastModifiedTime(file).toMillis();
    } catch (Exception e) {
      return Map.of();
    }
    Loaded l = loaded;
    if (l != null && l.file().equals(file) && l.modified() == modified) return l.rules();
    synchronized (this) {
      l = loaded;
      if (l != null && l.file().equals(file) && l.modified() == modified) return l.rules();
      Map<Long, RuleInfo> parsed = parse(file);
      loaded = new Loaded(file, modified, parsed);
      log.info("Indexed {} IDS rules' metadata from {}", parsed.size(), file);
      return parsed;
    }
  }

  static Map<Long, RuleInfo> parse(Path file) {
    Map<Long, RuleInfo> out = new HashMap<>();
    try (BufferedReader r = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
      String line;
      while ((line = r.readLine()) != null) {
        RuleInfo info = parseLine(line);
        if (info == null) continue;
        Matcher sid = SID.matcher(line);
        if (sid.find()) out.put(Long.parseLong(sid.group(1)), info);
      }
    } catch (Exception e) {
      log.warn("Could not read IDS rule metadata from {}: {}", file, e.getMessage());
    }
    return out;
  }

  /** One rule line's metadata, or null for a comment, a blank or a disabled rule. */
  static RuleInfo parseLine(String line) {
    String t = line.stripLeading();
    if (t.isEmpty() || t.startsWith("#")) return null;
    Matcher meta = METADATA.matcher(line);
    if (!meta.find()) return new RuleInfo(false, null);
    Matcher fam = FAMILY.matcher(meta.group(1));
    String family = fam.find() ? fam.group(1).trim().replace('_', ' ') : null;
    return new RuleInfo(true, family == null || family.isBlank() ? null : family);
  }
}
