package com.tracepcap.signatures.service;

import com.tracepcap.common.exception.FieldValidationException;
import com.tracepcap.signatures.dto.DetectionRuleRequest;
import com.tracepcap.signatures.dto.DetectionRuleRequest.Match;
import com.tracepcap.signatures.dto.DetectionRuleRequest.PayloadPattern;
import com.tracepcap.signatures.dto.DetectionRuleRequest.RegexPattern;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

/**
 * The one definition of a detection rule's shape (#925): validation, the YAML-shaped maps the
 * matching engine and the database store, and the YAML file format used by export, import and the
 * one-time upgrade from signatures.yml. Static, so the Flyway import (V51) can use it too.
 */
public final class RuleCodec {

  private static final Set<String> SEVERITIES = Set.of("low", "medium", "high", "critical");
  private static final Pattern HEX = Pattern.compile("[0-9a-f]*");
  private static final Pattern JA3 = Pattern.compile("[0-9a-fA-F]{32}");
  private static final Pattern IP_LITERAL = Pattern.compile("[0-9a-fA-F:.]+");

  /** A rule read from a file: the editable fields plus the legacy device_type, if any. */
  public record ParsedRule(DetectionRuleRequest rule, String deviceType) {}

  private RuleCodec() {}

  // ── Validation ───────────────────────────────────────────────────────────────

  /**
   * Checks what bean validation can't: at least one criterion, valid IP/CIDR/ports/JA3, one of
   * ascii or hex per payload pattern, valid hex, compiling regexes. Keys are field paths, such as
   * {@code match.cidr} or {@code payloadRegex[0].pattern}. Empty when valid.
   */
  public static Map<String, String> validate(DetectionRuleRequest r) {
    Map<String, String> errors = new LinkedHashMap<>();
    if (r.getName() == null || r.getName().isBlank()) errors.put("name", "Give the rule a name.");
    else if (r.getName().length() > 200) errors.put("name", "Keep the name under 200 characters.");
    if (r.getSeverity() == null || !SEVERITIES.contains(r.getSeverity())) {
      errors.put("severity", "Choose low, medium, high or critical.");
    }
    Match m = r.getMatch();
    boolean hasMatch = m != null && !toMatchMap(m).isEmpty();
    boolean hasPayload = r.getPayloadContains() != null && !r.getPayloadContains().isEmpty();
    boolean hasRegex = r.getPayloadRegex() != null && !r.getPayloadRegex().isEmpty();
    if (!hasMatch && !hasPayload && !hasRegex) {
      errors.put("match", "Add at least one match field or payload pattern, or the rule never fires.");
    }
    if (m != null) {
      if (notBlank(m.getIp()) && !isIp(m.getIp().trim())) errors.put("match.ip", "Not a valid IP address.");
      if (notBlank(m.getCidr()) && !isCidr(m.getCidr().trim())) {
        errors.put("match.cidr", "Not a valid CIDR range, such as 10.0.0.0/8.");
      }
      if (m.getSrcPort() != null && (m.getSrcPort() < 0 || m.getSrcPort() > 65535)) {
        errors.put("match.srcPort", "A port is 0 to 65535.");
      }
      if (m.getDstPort() != null && (m.getDstPort() < 0 || m.getDstPort() > 65535)) {
        errors.put("match.dstPort", "A port is 0 to 65535.");
      }
      if (notBlank(m.getJa3()) && !JA3.matcher(m.getJa3().trim()).matches()) {
        errors.put("match.ja3", "A JA3 hash is 32 hex characters.");
      }
    }
    if (hasPayload) {
      for (int i = 0; i < r.getPayloadContains().size(); i++) {
        PayloadPattern p = r.getPayloadContains().get(i);
        String key = "payloadContains[" + i + "]";
        boolean ascii = p != null && notBlank(p.getAscii());
        boolean hex = p != null && notBlank(p.getHex());
        if (ascii == hex) errors.put(key, "Give either text or hex bytes, not both or neither.");
        else if (hex) {
          String h = normaliseHex(p.getHex());
          if (h.isEmpty() || h.length() % 2 != 0 || !HEX.matcher(h).matches()) {
            errors.put(key + ".hex", "Hex bytes are pairs of 0-9 and a-f, such as 48 54 54 50.");
          }
        }
      }
    }
    if (r.getDeviceTypeWeight() != null && (r.getDeviceTypeWeight() < 1 || r.getDeviceTypeWeight() > 100)) {
      errors.put("deviceTypeWeight", "A weight is 1 to 100.");
    }
    if (hasRegex) {
      for (int i = 0; i < r.getPayloadRegex().size(); i++) {
        RegexPattern p = r.getPayloadRegex().get(i);
        String key = "payloadRegex[" + i + "].pattern";
        if (p == null || !notBlank(p.getPattern())) {
          errors.put(key, "Enter a pattern.");
          continue;
        }
        try {
          Pattern.compile(p.getPattern());
        } catch (PatternSyntaxException e) {
          errors.put(key, "Not a valid regular expression: " + e.getDescription() + ".");
        }
      }
    }
    return errors;
  }

  // ── Request ⇄ stored (YAML-shaped) maps ───────────────────────────────────────

  public static Map<String, Object> toMatchMap(Match m) {
    Map<String, Object> out = new LinkedHashMap<>();
    if (m == null) return out;
    putIfText(out, "ip", m.getIp());
    putIfText(out, "cidr", m.getCidr());
    if (m.getSrcPort() != null) out.put("srcPort", m.getSrcPort());
    if (m.getDstPort() != null) out.put("dstPort", m.getDstPort());
    putIfText(out, "ja3", m.getJa3());
    putIfText(out, "hostname", m.getHostname());
    putIfText(out, "app", m.getApp());
    putIfText(out, "protocol", m.getProtocol());
    return out;
  }

  public static List<Map<String, Object>> toPayloadContains(List<PayloadPattern> list) {
    List<Map<String, Object>> out = new ArrayList<>();
    if (list == null) return out;
    for (PayloadPattern p : list) {
      if (p == null) continue;
      if (notBlank(p.getAscii())) out.add(Map.of("ascii", p.getAscii()));
      else if (notBlank(p.getHex())) out.add(Map.of("hex", p.getHex().trim()));
    }
    return out;
  }

  public static List<Map<String, Object>> toPayloadRegex(List<RegexPattern> list) {
    List<Map<String, Object>> out = new ArrayList<>();
    if (list == null) return out;
    for (RegexPattern p : list) {
      if (p == null || !notBlank(p.getPattern())) continue;
      Map<String, Object> e = new LinkedHashMap<>();
      e.put("pattern", p.getPattern());
      if (p.isCaseInsensitive()) e.put("case_insensitive", true);
      out.add(e);
    }
    return out;
  }

  public static Match fromMatchMap(Map<String, Object> m) {
    if (m == null) m = Map.of();
    return Match.builder()
        .ip(text(m.get("ip")))
        .cidr(text(m.get("cidr")))
        .srcPort(integer(m.get("srcPort")))
        .dstPort(integer(m.get("dstPort")))
        .ja3(text(m.get("ja3")))
        .hostname(text(m.get("hostname")))
        .app(text(m.get("app")))
        .protocol(text(m.get("protocol")))
        .build();
  }

  public static List<PayloadPattern> fromPayloadContains(List<Map<String, Object>> list) {
    List<PayloadPattern> out = new ArrayList<>();
    if (list == null) return out;
    for (Object o : list) {
      if (!(o instanceof Map<?, ?> m)) continue;
      out.add(PayloadPattern.builder().ascii(text(m.get("ascii"))).hex(text(m.get("hex"))).build());
    }
    return out;
  }

  public static List<RegexPattern> fromPayloadRegex(List<Map<String, Object>> list) {
    List<RegexPattern> out = new ArrayList<>();
    if (list == null) return out;
    for (Object o : list) {
      if (!(o instanceof Map<?, ?> m)) continue;
      out.add(
          RegexPattern.builder()
              .pattern(text(m.get("pattern")))
              .caseInsensitive(Boolean.TRUE.equals(m.get("case_insensitive")))
              .build());
    }
    return out;
  }

  // ── YAML file format ─────────────────────────────────────────────────────────

  /**
   * Reads a rules file: TracePcap's export, or an old signatures.yml ({@code signatures:} list).
   * Throws {@link FieldValidationException} on a YAML syntax error. Entries without a name are
   * reported as errors; unknown keys are ignored.
   */
  @SuppressWarnings("unchecked")
  public static List<ParsedRule> parseYaml(String content) {
    Object root;
    try {
      root = new Yaml(new SafeConstructor(new LoaderOptions())).load(content == null ? "" : content);
    } catch (Exception e) {
      throw new FieldValidationException(
          "The file isn't valid YAML", Map.of("content", "Not valid YAML: " + firstLine(e.getMessage())));
    }
    if (root == null) return List.of();
    if (!(root instanceof Map<?, ?> map) || !(map.get("signatures") == null || map.get("signatures") instanceof List)) {
      throw new FieldValidationException(
          "Not a rules file", Map.of("content", "Expected a top-level \"signatures:\" list of rules."));
    }
    List<?> raw = map.get("signatures") == null ? List.of() : (List<?>) map.get("signatures");
    List<ParsedRule> out = new ArrayList<>();
    for (Object item : raw) {
      if (!(item instanceof Map<?, ?> r)) continue;
      Map<String, Object> rule = (Map<String, Object>) r;
      Object match = rule.get("match");
      Object pc = rule.get("payload_contains");
      Object pr = rule.get("payload_regex");
      String severity = text(rule.get("severity"));
      DetectionRuleRequest req =
          DetectionRuleRequest.builder()
              .name(text(rule.get("name")))
              .description(text(rule.get("description")))
              .severity(severity == null ? "low" : severity.toLowerCase())
              .enabled(!Boolean.FALSE.equals(rule.get("enabled")))
              .match(match instanceof Map<?, ?> mm ? fromMatchMap((Map<String, Object>) mm) : null)
              .payloadContains(pc instanceof List<?> l ? fromPayloadContains((List<Map<String, Object>>) l) : null)
              .payloadRegex(pr instanceof List<?> l ? fromPayloadRegex((List<Map<String, Object>>) l) : null)
              .matchAll(Boolean.TRUE.equals(rule.get("match_all")))
              .build();
      String deviceType = text(rule.get("device_type"));
      if (deviceType != null && rule.containsKey("device_type_weight")) {
        // A file from #926 on: the hint and its weight. An old file has no weight; the caller
        // decides what that means (a strong hint, since it used to be an override).
        req.setDeviceType(deviceType);
        req.setDeviceTypeWeight(integer(rule.get("device_type_weight")));
      }
      out.add(new ParsedRule(req, deviceType));
    }
    return out;
  }

  /** One rule in the file format, in a stable key order. */
  public static Map<String, Object> toYamlMap(
      DetectionRuleRequest r, String deviceType) {
    Map<String, Object> out = new LinkedHashMap<>();
    out.put("name", r.getName());
    if (notBlank(r.getDescription())) out.put("description", r.getDescription());
    out.put("severity", r.getSeverity());
    if (!r.isEnabled()) out.put("enabled", false);
    Map<String, Object> match = toMatchMap(r.getMatch());
    if (!match.isEmpty()) out.put("match", match);
    List<Map<String, Object>> pc = toPayloadContains(r.getPayloadContains());
    if (!pc.isEmpty()) out.put("payload_contains", pc);
    List<Map<String, Object>> pr = toPayloadRegex(r.getPayloadRegex());
    if (!pr.isEmpty()) out.put("payload_regex", pr);
    if (r.isMatchAll()) out.put("match_all", true);
    String type = notBlank(r.getDeviceType()) ? r.getDeviceType() : deviceType;
    if (notBlank(type)) {
      out.put("device_type", type);
      out.put("device_type_weight", r.getDeviceTypeWeight() != null ? r.getDeviceTypeWeight() : 80);
    }
    return out;
  }

  public static String formatYaml(List<Map<String, Object>> rules, String header) {
    DumperOptions opts = new DumperOptions();
    opts.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
    opts.setIndent(2);
    opts.setIndicatorIndent(0);
    opts.setPrettyFlow(true);
    Map<String, Object> root = new LinkedHashMap<>();
    root.put("signatures", rules);
    return header + new Yaml(opts).dump(root);
  }

  // ── helpers ──────────────────────────────────────────────────────────────────

  static String normaliseHex(String hex) {
    String s = hex.toLowerCase().trim();
    if (s.startsWith("0x")) s = s.substring(2);
    return s.replaceAll("[\\s:\\-]", "");
  }

  private static boolean isIp(String s) {
    // Literal check first: InetAddress.getByName would otherwise do a DNS lookup on a hostname.
    if (!IP_LITERAL.matcher(s).matches()) return false;
    try {
      InetAddress.getByName(s);
      return true;
    } catch (Exception e) {
      return false;
    }
  }

  private static boolean isCidr(String s) {
    String[] parts = s.split("/");
    if (parts.length != 2 || !isIp(parts[0])) return false;
    try {
      int len = Integer.parseInt(parts[1]);
      int max = parts[0].contains(":") ? 128 : 32;
      return len >= 0 && len <= max;
    } catch (NumberFormatException e) {
      return false;
    }
  }

  private static boolean notBlank(String s) {
    return s != null && !s.isBlank();
  }

  private static void putIfText(Map<String, Object> out, String key, String v) {
    if (notBlank(v)) out.put(key, v.trim());
  }

  private static String text(Object o) {
    if (o == null) return null;
    String s = o.toString();
    return s.isBlank() ? null : s;
  }

  private static Integer integer(Object o) {
    if (o == null) return null;
    if (o instanceof Number n) return n.intValue();
    try {
      return Integer.parseInt(o.toString().trim());
    } catch (NumberFormatException e) {
      // Not null: dropping the field would silently widen the rule. -1 fails validation instead.
      return -1;
    }
  }

  private static String firstLine(String s) {
    if (s == null) return "";
    int nl = s.indexOf('\n');
    return nl < 0 ? s : s.substring(0, nl);
  }
}
