package com.tracepcap.analysis.service;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.constructor.SafeConstructor;

/**
 * Loads custom detection rules from {@code signatures.yml} and applies them to each conversation
 * after nDPI enrichment. Matched rule names are appended to the conversation's {@code flowRisks}
 * list, making them visible in the Risk Type filter and security alerts alongside nDPI's built-in
 * flags.
 *
 * <p>The file is reloaded on every analysis run so admins can update rules without restarting the
 * application.
 *
 * <p>Supported match fields (all optional; a rule fires when ALL specified fields match):
 * <ul>
 *   <li>{@code ip}      — exact match against srcIp OR dstIp</li>
 *   <li>{@code cidr}    — CIDR range match against srcIp OR dstIp (e.g. {@code 10.0.0.0/8})</li>
 *   <li>{@code srcPort} — exact match against source port</li>
 *   <li>{@code dstPort} — exact match against destination port</li>
 *   <li>{@code ja3}     — exact match against ja3Client OR ja3Server</li>
 *   <li>{@code hostname}— exact or wildcard match against SNI hostname (e.g. {@code *.evil.com})</li>
 *   <li>{@code app}      — case-insensitive match against nDPI appName</li>
 *   <li>{@code protocol} — case-insensitive match against transport/network protocol (e.g. TCP, UDP, ICMP)</li>
 * </ul>
 */
@Slf4j
@Service
public class CustomSignatureService {

  @Value("${tracepcap.signatures.path:/app/config/signatures.yml}")
  private String signaturesPath;

  /**
   * Evaluates all loaded rules against each conversation and appends matched rule names to the
   * conversation's {@code flowRisks} list in-place.
   */
  public void applySignatures(List<PcapParserService.ConversationInfo> conversations) {
    List<Map<String, Object>> rules = loadRules();
    if (rules.isEmpty() || conversations.isEmpty()) return;

    int matchCount = 0;
    for (PcapParserService.ConversationInfo conv : conversations) {
      for (Map<String, Object> rule : rules) {
        String name = (String) rule.get("name");
        if (name == null || name.isBlank()) continue;

        @SuppressWarnings("unchecked")
        Map<String, Object> match = (Map<String, Object>) rule.get("match");
        if (match == null || match.isEmpty()) continue;

        if (matches(conv, match)) {
          if (!conv.getCustomSignatures().contains(name)) {
            conv.getCustomSignatures().add(name);
            matchCount++;
          }
        }
      }
    }
    if (matchCount > 0) {
      log.info("Custom signatures: {} match(es) across {} conversations", matchCount, conversations.size());
    }
  }

  // -------------------------------------------------------------------------
  // Internal helpers
  // -------------------------------------------------------------------------

  /** Load and parse the signatures file. Returns an empty list if the file is missing or invalid. */
  @SuppressWarnings("unchecked")
  private List<Map<String, Object>> loadRules() {
    File file = new File(signaturesPath);
    if (!file.exists()) {
      return List.of();
    }

    try (FileInputStream fis = new FileInputStream(file)) {
      Yaml yaml = new Yaml(new SafeConstructor(new LoaderOptions()));
      Map<String, Object> root = yaml.load(fis);
      if (root == null || !root.containsKey("signatures")) return List.of();

      Object signaturesObj = root.get("signatures");
      if (!(signaturesObj instanceof List)) return List.of();

      List<?> raw = (List<?>) signaturesObj;
      List<Map<String, Object>> rules = new ArrayList<>();
      for (Object item : raw) {
        if (item instanceof Map) {
          rules.add((Map<String, Object>) item);
        }
      }
      return rules;
    } catch (IOException e) {
      log.warn("Could not read signatures file at {}: {}", signaturesPath, e.getMessage());
      return List.of();
    } catch (Exception e) {
      log.warn("Failed to parse signatures file at {}: {}", signaturesPath, e.getMessage());
      return List.of();
    }
  }

  /** Returns true if the conversation satisfies ALL non-null criteria in the match block. */
  private boolean matches(PcapParserService.ConversationInfo conv, Map<String, Object> match) {
    // ip — exact match against srcIp OR dstIp
    if (match.containsKey("ip")) {
      String ip = (String) match.get("ip");
      if (!ip.equals(conv.getSrcIp()) && !ip.equals(conv.getDstIp())) return false;
    }

    // cidr — CIDR range match against srcIp OR dstIp
    if (match.containsKey("cidr")) {
      String cidr = (String) match.get("cidr");
      if (!inCidr(conv.getSrcIp(), cidr) && !inCidr(conv.getDstIp(), cidr)) return false;
    }

    // srcPort — exact match
    if (match.containsKey("srcPort")) {
      int port = toInt(match.get("srcPort"));
      if (!Integer.valueOf(port).equals(conv.getSrcPort())) return false;
    }

    // dstPort — exact match
    if (match.containsKey("dstPort")) {
      int port = toInt(match.get("dstPort"));
      if (!Integer.valueOf(port).equals(conv.getDstPort())) return false;
    }

    // ja3 — exact match against ja3Client OR ja3Server
    if (match.containsKey("ja3")) {
      String ja3 = (String) match.get("ja3");
      boolean clientMatch = ja3.equals(conv.getJa3Client());
      boolean serverMatch = ja3.equals(conv.getJa3Server());
      if (!clientMatch && !serverMatch) return false;
    }

    // hostname — exact or wildcard match against SNI hostname
    if (match.containsKey("hostname")) {
      String pattern = (String) match.get("hostname");
      if (!hostnameMatches(conv.getHostname(), pattern)) return false;
    }

    // app — case-insensitive match against nDPI appName
    if (match.containsKey("app")) {
      String app = (String) match.get("app");
      if (conv.getAppName() == null || !app.equalsIgnoreCase(conv.getAppName())) return false;
    }

    // protocol — case-insensitive match against transport/network protocol (e.g. TCP, UDP, ICMP)
    if (match.containsKey("protocol")) {
      String protocol = (String) match.get("protocol");
      if (conv.getProtocol() == null || !protocol.equalsIgnoreCase(conv.getProtocol())) return false;
    }

    return true;
  }

  /** Returns true if {@code ip} falls within the given CIDR range. */
  private boolean inCidr(String ip, String cidr) {
    if (ip == null || cidr == null) return false;
    try {
      String[] parts = cidr.split("/");
      if (parts.length != 2) return false;
      int prefixLen = Integer.parseInt(parts[1]);

      InetAddress network = InetAddress.getByName(parts[0]);
      InetAddress address = InetAddress.getByName(ip);

      // Must be the same address family
      byte[] netBytes = network.getAddress();
      byte[] addrBytes = address.getAddress();
      if (netBytes.length != addrBytes.length) return false;

      // Compare the first prefixLen bits
      int fullBytes = prefixLen / 8;
      int remainingBits = prefixLen % 8;

      for (int i = 0; i < fullBytes; i++) {
        if (netBytes[i] != addrBytes[i]) return false;
      }
      if (remainingBits > 0 && fullBytes < netBytes.length) {
        int mask = 0xFF & (0xFF << (8 - remainingBits));
        if ((netBytes[fullBytes] & mask) != (addrBytes[fullBytes] & mask)) return false;
      }
      return true;
    } catch (UnknownHostException | NumberFormatException e) {
      log.warn("Invalid CIDR '{}': {}", cidr, e.getMessage());
      return false;
    }
  }

  /**
   * Matches a hostname against a pattern. Supports a single leading wildcard: {@code *.example.com}
   * matches {@code foo.example.com} and {@code example.com} but not {@code foo.bar.example.com}.
   */
  private boolean hostnameMatches(String hostname, String pattern) {
    if (hostname == null || pattern == null) return false;
    if (!pattern.startsWith("*.")) {
      return pattern.equalsIgnoreCase(hostname);
    }
    // Wildcard: strip the "*." and check that hostname ends with the remainder,
    // preceded by a "." or equal to it (covers the apex domain itself)
    String suffix = pattern.substring(2).toLowerCase();
    String h = hostname.toLowerCase();
    return h.equals(suffix) || h.endsWith("." + suffix);
  }

  private int toInt(Object value) {
    if (value instanceof Number) return ((Number) value).intValue();
    return Integer.parseInt(value.toString());
  }
}
