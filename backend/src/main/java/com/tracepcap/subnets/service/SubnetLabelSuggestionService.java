package com.tracepcap.subnets.service;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracepcap.common.exception.InsufficientEvidenceException;
import com.tracepcap.common.exception.ResourceNotFoundException;
import com.tracepcap.monitor.entity.NetworkSnapshotEntity;
import com.tracepcap.monitor.repository.NetworkSnapshotRepository;
import com.tracepcap.subnets.dto.SubnetLabelSuggestionDto;
import com.tracepcap.subnets.entity.SubnetDefinitionEntity;
import com.tracepcap.subnets.repository.SubnetDefinitionRepository;
import com.tracepcap.story.service.LlmClient;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Suggests a label + description for a subnet from the observed behaviour of its member nodes (#363).
 * Collects the member nodes of a subnet's CIDR across the most recent snapshots, summarises each
 * node's behaviour (device type, role label, dominant protocols, external orgs), and asks the LLM for
 * a concise subnet name plus a description of its purpose and any anomalies. The result is <b>not</b>
 * persisted — the analyst reviews it in the edit form and saves it onto the subnet's own fields.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SubnetLabelSuggestionService {

  /** How many recent snapshots to scan when scoped to a network. */
  private static final int MAX_SNAPSHOTS = 5;

  /** Cap on member nodes fed to the LLM, to keep the prompt within context. */
  private static final int MAX_MEMBERS = 40;

  private static final ObjectMapper LENIENT_MAPPER =
      new ObjectMapper().enable(JsonParser.Feature.ALLOW_COMMENTS);

  private final SubnetDefinitionRepository subnetRepo;
  private final NetworkSnapshotRepository snapshotRepo;
  private final LlmClient llmClient;
  private final org.springframework.jdbc.core.JdbcTemplate jdbc;

  /**
   * Ask the LLM to suggest a label + description for a subnet from its member nodes' behaviour. If
   * {@code networkId} is provided the scan is scoped to that network's most recent snapshots;
   * otherwise all captures are considered. Nothing is persisted.
   */
  public SubnetLabelSuggestionDto suggest(Long subnetId, UUID networkId, UUID fileId) {
    SubnetDefinitionEntity subnet =
        subnetRepo
            .findById(subnetId)
            .orElseThrow(() -> new ResourceNotFoundException("Subnet not found: " + subnetId));

    long[] range = cidrRange(subnet.getCidr());
    // A specific fileId scopes the suggestion to that one snapshot's traffic (per-snapshot AI);
    // otherwise fall back to the network's recent snapshots.
    List<UUID> fileIds = fileId != null ? List.of(fileId) : resolveFileIds(networkId);

    List<MemberNode> members = collectMembers(fileIds, range[0], range[1]);
    if (members.isEmpty()) {
      throw new InsufficientEvidenceException(
          "No member nodes were observed in " + subnet.getCidr() + " across the scanned captures.");
    }

    String context = buildContext(members);
    String raw = llmClient.generateCompletion(buildSystemPrompt(), buildUserPrompt(subnet.getCidr(), context));
    Suggestion parsed = parse(raw);

    return SubnetLabelSuggestionDto.builder()
        .label(parsed.label())
        .description(parsed.description())
        .memberCount(members.size())
        .snapshotCount(fileIds.size())
        .build();
  }

  // ── data collection ─────────────────────────────────────────────────────────

  /** File ids to scan: a network's most recent N snapshots, or all files when unscoped. */
  private List<UUID> resolveFileIds(UUID networkId) {
    if (networkId != null) {
      List<NetworkSnapshotEntity> snaps =
          snapshotRepo.findByNetworkIdOrderBySnapshotOrderAsc(networkId);
      return snaps.stream()
          .filter(s -> s.getFile() != null)
          .sorted(Comparator.comparingInt(NetworkSnapshotEntity::getSnapshotOrder).reversed())
          .limit(MAX_SNAPSHOTS)
          .map(s -> s.getFile().getId())
          .collect(Collectors.toList());
    }
    // Unscoped: every file we have host classifications for.
    return jdbc.query(
        "SELECT DISTINCT file_id FROM host_classifications",
        (rs, i) -> (UUID) rs.getObject("file_id"));
  }

  /** One member node with its behavioural summary, aggregated across the scanned files. */
  private record MemberNode(
      String ip,
      String deviceType,
      Integer confidence,
      String manufacturer,
      String roleLabel,
      List<String> protocols,
      List<String> externalOrgs) {}

  private List<MemberNode> collectMembers(List<UUID> fileIds, long lo, long hi) {
    if (fileIds.isEmpty()) return List.of();

    // IPs inside the CIDR, with their best host classification across the scanned files.
    String hostSql =
        """
        SELECT DISTINCT ON (hc.ip) hc.ip, hc.device_type, hc.confidence, hc.manufacturer
        FROM host_classifications hc
        WHERE hc.file_id = ANY(?)
          AND ip_to_int(hc.ip) BETWEEN ? AND ?
        ORDER BY hc.ip, hc.confidence DESC
        """;

    List<MemberNode> members = new ArrayList<>();
    UUID[] fileIdArray = fileIds.toArray(new UUID[0]);
    List<Object[]> rows;
    try {
      rows =
          jdbc.query(
              con -> {
                var ps = con.prepareStatement(hostSql);
                ps.setArray(1, con.createArrayOf("uuid", fileIdArray));
                ps.setLong(2, lo);
                ps.setLong(3, hi);
                return ps;
              },
              (rs, i) ->
                  new Object[] {
                    rs.getString("ip"),
                    rs.getString("device_type"),
                    (Integer) rs.getObject("confidence"),
                    rs.getString("manufacturer")
                  });
    } catch (Exception e) {
      log.warn("Failed to enumerate subnet members: {}", e.getMessage());
      return List.of();
    }

    for (Object[] row : rows) {
      if (members.size() >= MAX_MEMBERS) break;
      String ip = (String) row[0];
      members.add(
          new MemberNode(
              ip,
              (String) row[1],
              (Integer) row[2],
              (String) row[3],
              lookupRoleLabel(fileIds, ip),
              lookupProtocols(fileIds, ip),
              lookupExternalOrgs(fileIds, ip, lo, hi)));
    }
    return members;
  }

  private String lookupRoleLabel(List<UUID> fileIds, String ip) {
    try {
      List<String> labels =
          jdbc.query(
              con -> {
                var ps =
                    con.prepareStatement(
                        """
                        SELECT role_label FROM node_roles
                        WHERE file_id = ANY(?) AND entity_type = 'IP' AND entity_key = ?
                          AND role_label IS NOT NULL
                        ORDER BY confirmed_by_human DESC, updated_at DESC LIMIT 1
                        """);
                ps.setArray(1, con.createArrayOf("uuid", fileIds.toArray(new UUID[0])));
                ps.setString(2, ip);
                return ps;
              },
              (rs, i) -> rs.getString("role_label"));
      return labels.isEmpty() ? null : labels.get(0);
    } catch (Exception e) {
      log.debug("Role label lookup failed for {}: {}", ip, e.getMessage());
      return null;
    }
  }

  private List<String> lookupProtocols(List<UUID> fileIds, String ip) {
    try {
      return jdbc.query(
          con -> {
            var ps =
                con.prepareStatement(
                    """
                    SELECT tshark_protocol FROM conversations
                    WHERE file_id = ANY(?) AND (src_ip = ? OR dst_ip = ?)
                      AND tshark_protocol IS NOT NULL
                    GROUP BY tshark_protocol ORDER BY COUNT(*) DESC LIMIT 6
                    """);
            ps.setArray(1, con.createArrayOf("uuid", fileIds.toArray(new UUID[0])));
            ps.setString(2, ip);
            ps.setString(3, ip);
            return ps;
          },
          (rs, i) -> rs.getString("tshark_protocol"));
    } catch (Exception e) {
      log.debug("Protocol lookup failed for {}: {}", ip, e.getMessage());
      return List.of();
    }
  }

  /** Top external orgs this member talked to (dst outside the subnet, joined to geo cache). */
  private List<String> lookupExternalOrgs(List<UUID> fileIds, String ip, long lo, long hi) {
    try {
      return jdbc.query(
          con -> {
            var ps =
                con.prepareStatement(
                    """
                    SELECT g.org FROM conversations c
                    JOIN ip_geo_cache g ON g.ip = c.dst_ip
                    WHERE c.file_id = ANY(?) AND c.src_ip = ?
                      AND g.org IS NOT NULL
                      AND (ip_to_int(c.dst_ip) IS NULL
                           OR ip_to_int(c.dst_ip) NOT BETWEEN ? AND ?)
                    GROUP BY g.org ORDER BY COUNT(*) DESC LIMIT 4
                    """);
            ps.setArray(1, con.createArrayOf("uuid", fileIds.toArray(new UUID[0])));
            ps.setString(2, ip);
            ps.setLong(3, lo);
            ps.setLong(4, hi);
            return ps;
          },
          (rs, i) -> rs.getString("org"));
    } catch (Exception e) {
      log.debug("External org lookup failed for {}: {}", ip, e.getMessage());
      return List.of();
    }
  }

  // ── prompt building ─────────────────────────────────────────────────────────

  private String buildContext(List<MemberNode> members) {
    StringBuilder sb = new StringBuilder();
    sb.append("Member nodes (").append(members.size()).append("):\n");
    for (MemberNode m : members) {
      sb.append("- ").append(m.ip());
      if (m.deviceType() != null) {
        sb.append(" | type: ").append(m.deviceType());
        if (m.confidence() != null) sb.append(" (").append(m.confidence()).append("%)");
      }
      if (m.manufacturer() != null) sb.append(" | vendor: ").append(m.manufacturer());
      if (m.roleLabel() != null) sb.append(" | role: ").append(m.roleLabel());
      if (!m.protocols().isEmpty()) {
        sb.append(" | protocols: ").append(String.join(", ", m.protocols()));
      }
      if (!m.externalOrgs().isEmpty()) {
        sb.append(" | talks to: ").append(String.join(", ", m.externalOrgs()));
      }
      sb.append("\n");
    }
    return sb.toString();
  }

  private String buildSystemPrompt() {
    return """
        You are a network analyst. Given the observed behaviour of the member hosts of a single
        subnet, suggest a concise LABEL naming what the subnet is (e.g. "IoT sensor cluster",
        "Corporate user workstations", "DMZ / public-facing services", "Server / datacentre segment",
        "OT / ICS control network", "Guest / BYOD network"), and a DESCRIPTION covering its likely
        purpose, key observations, and any anomalies (e.g. a spoofing indicator, an unexpected device
        type, or traffic to an unusual external org).
        Base your answer ONLY on the evidence given — this is observational, not a full inventory.
        The label should be 2-6 words. The description should be 2-5 sentences of plain prose.
        Respond ONLY with valid JSON in the format:
        {"label": "...", "description": "..."}
        If the evidence is too sparse to say anything meaningful, respond with:
        {"label": null, "description": "Not enough evidence to characterise this subnet."}
        Do not add any text outside the JSON.
        """;
  }

  private String buildUserPrompt(String cidr, String context) {
    return String.format(
        """
        ## Subnet
        CIDR: %s

        ## Observed member behaviour
        %s

        Suggest a label and description for this subnet.
        Respond ONLY with valid JSON: {"label": "...", "description": "..."}
        """,
        cidr, context);
  }

  private record Suggestion(String label, String description) {}

  private Suggestion parse(String raw) {
    String json = extractJson(raw);
    try {
      Map<String, Object> data = LENIENT_MAPPER.readValue(json, new TypeReference<>() {});
      Object labelRaw = data.get("label");
      Object descRaw = data.get("description");
      String description = descRaw != null ? descRaw.toString().trim() : "";
      if (description.isBlank() && (labelRaw == null || labelRaw.toString().isBlank())) {
        throw new InsufficientEvidenceException(
            "The model returned an empty suggestion for this subnet.");
      }
      String label =
          labelRaw != null && !labelRaw.toString().isBlank() ? labelRaw.toString().trim() : null;
      return new Suggestion(label, description);
    } catch (InsufficientEvidenceException e) {
      throw e;
    } catch (Exception e) {
      log.warn("Failed to parse LLM subnet label suggestion: {}", e.getMessage());
      throw new RuntimeException("Failed to parse LLM subnet label suggestion", e);
    }
  }

  private String extractJson(String content) {
    if (content == null || content.isBlank()) throw new RuntimeException("Empty LLM response");
    content = content.replaceAll("```json\\s*", "").replaceAll("```\\s*", "");
    int start = content.indexOf('{');
    int end = content.lastIndexOf('}');
    if (start >= 0 && end > start) return content.substring(start, end + 1);
    return content;
  }

  // ── helpers ───────────────────────────────────────────────────────────────

  /** Inclusive [network, broadcast] integer range for an IPv4 CIDR. */
  private static long[] cidrRange(String cidr) {
    String[] parts = cidr.split("/");
    long base = ipToLong(parts[0]);
    int prefix = Integer.parseInt(parts[1]);
    long mask = prefix == 0 ? 0L : (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
    long network = base & mask;
    long broadcast = network | (~mask & 0xFFFFFFFFL);
    return new long[] {network, broadcast};
  }

  private static long ipToLong(String ip) {
    String[] o = ip.split("\\.");
    long v = 0;
    for (String part : o) v = (v << 8) | Integer.parseInt(part);
    return v;
  }
}
