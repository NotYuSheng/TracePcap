package com.tracepcap.insights.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracepcap.analysis.repository.HostClassificationRepository;
import com.tracepcap.insights.dto.NodeRoleDto;
import com.tracepcap.insights.dto.UpsertNodeRoleRequest;
import com.tracepcap.insights.entity.NodeRoleEntity;
import com.tracepcap.insights.repository.NodeRoleRepository;
import com.tracepcap.story.service.LlmClient;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class NodeRoleService {

  private final NodeRoleRepository nodeRoleRepository;
  private final HostClassificationRepository hostClassificationRepository;
  private final LlmClient llmClient;
  private final ObjectMapper objectMapper;
  private final JdbcTemplate jdbc;

  public Optional<NodeRoleDto> getRole(String entityType, String entityKey) {
    return nodeRoleRepository
        .findByEntityTypeAndEntityKey(entityType, entityKey)
        .map(this::toDto);
  }

  @Transactional
  public NodeRoleDto upsert(UpsertNodeRoleRequest req) {
    NodeRoleEntity entity =
        nodeRoleRepository
            .findByEntityTypeAndEntityKey(req.getEntityType(), req.getEntityKey())
            .orElseGet(
                () ->
                    NodeRoleEntity.builder()
                        .entityType(req.getEntityType())
                        .entityKey(req.getEntityKey())
                        .build());
    entity.setRoleLabel(req.getRoleLabel());
    entity.setRoleDescription(req.getRoleDescription());
    entity.setConfirmedByHuman(req.isConfirmedByHuman());
    // Once confirmed by a human, keep llmSuggested as-is; only clear it when human explicitly saves
    if (req.isConfirmedByHuman()) {
      entity.setLlmSuggested(false);
    }
    return toDto(nodeRoleRepository.save(entity));
  }

  @Transactional
  public void delete(String entityType, String entityKey) {
    nodeRoleRepository.deleteByEntityTypeAndEntityKey(entityType, entityKey);
  }

  /**
   * Ask the LLM to suggest an operational role for a node, given its host classification signals
   * and top apps/protocols from the specified file.
   */
  public NodeRoleDto suggestRole(String entityType, String entityKey, UUID fileId) {
    // Build context from host classifications and conversations
    String classificationContext = buildClassificationContext(entityType, entityKey, fileId);
    String systemPrompt = buildSuggestSystemPrompt();
    String userPrompt = buildSuggestUserPrompt(entityType, entityKey, classificationContext);

    String raw = llmClient.generateCompletion(systemPrompt, userPrompt);
    String json = extractJson(raw);

    try {
      Map<String, Object> data = objectMapper.readValue(json, new TypeReference<>() {});
      Object roleLabelRaw = data.get("roleLabel");
      Object roleDescRaw = data.get("roleDescription");

      // LLM indicated insufficient evidence
      if (roleLabelRaw == null || roleLabelRaw.toString().isBlank()) {
        throw new InsufficientEvidenceException(
            "Not enough traffic signals to make a meaningful role assessment for this entity.");
      }

      String roleLabel = roleLabelRaw.toString().trim();
      String roleDescription = roleDescRaw != null ? roleDescRaw.toString().trim() : "";

      NodeRoleEntity entity =
          nodeRoleRepository
              .findByEntityTypeAndEntityKey(entityType, entityKey)
              .orElseGet(
                  () ->
                      NodeRoleEntity.builder()
                          .entityType(entityType)
                          .entityKey(entityKey)
                          .build());
      // Only overwrite if there is no confirmed human role already
      if (!entity.isConfirmedByHuman()) {
        entity.setRoleLabel(roleLabel);
        entity.setRoleDescription(roleDescription);
        entity.setLlmSuggested(true);
        entity.setConfirmedByHuman(false);
        return toDto(nodeRoleRepository.save(entity));
      }
      return toDto(entity);
    } catch (InsufficientEvidenceException e) {
      throw e;
    } catch (Exception e) {
      log.warn("Failed to parse LLM role suggestion for {}/{}: {}", entityType, entityKey, e.getMessage());
      throw new RuntimeException("Failed to parse LLM role suggestion", e);
    }
  }

  // ── Private helpers ───────────────────────────────────────────────────────

  private String buildClassificationContext(String entityType, String entityKey, UUID fileId) {
    StringBuilder sb = new StringBuilder();

    if ("IP".equalsIgnoreCase(entityType)) {
      // Look up host classification for this IP in the given file
      hostClassificationRepository.findByFileIdAndIp(fileId, entityKey)
          .ifPresent(h -> {
            sb.append("Device type: ").append(h.getDeviceType())
              .append(" (confidence: ").append(h.getConfidence()).append("%)\n");
            if (h.getManufacturer() != null) sb.append("Manufacturer: ").append(h.getManufacturer()).append("\n");
            if (h.getTtl() != null) sb.append("TTL: ").append(h.getTtl()).append("\n");
            if (h.getMac() != null) sb.append("MAC: ").append(h.getMac()).append("\n");
          });

      // Top apps and protocols from conversations
      String appSql = """
          SELECT app_name, COUNT(*) as cnt
          FROM conversations
          WHERE (file_id = ? AND src_ip = ? OR file_id = ? AND dst_ip = ?)
            AND app_name IS NOT NULL
          GROUP BY app_name ORDER BY cnt DESC LIMIT 8
          """;
      try {
        List<String> apps = jdbc.query(appSql,
            (rs, i) -> rs.getString("app_name"),
            fileId, entityKey, fileId, entityKey);
        if (!apps.isEmpty()) sb.append("Applications: ").append(String.join(", ", apps)).append("\n");
      } catch (Exception e) {
        log.debug("Could not load apps for role suggestion: {}", e.getMessage());
      }

      String protoSql = """
          SELECT tshark_protocol, COUNT(*) as cnt
          FROM conversations
          WHERE (file_id = ? AND src_ip = ? OR file_id = ? AND dst_ip = ?)
            AND tshark_protocol IS NOT NULL
          GROUP BY tshark_protocol ORDER BY cnt DESC LIMIT 5
          """;
      try {
        List<String> protos = jdbc.query(protoSql,
            (rs, i) -> rs.getString("tshark_protocol"),
            fileId, entityKey, fileId, entityKey);
        if (!protos.isEmpty()) sb.append("Protocols: ").append(String.join(", ", protos)).append("\n");
      } catch (Exception e) {
        log.debug("Could not load protocols for role suggestion: {}", e.getMessage());
      }

    } else if ("DEVICE".equalsIgnoreCase(entityType)) {
      // MAC-based lookup
      hostClassificationRepository.findByFileIdAndMacIgnoreCase(fileId, entityKey)
          .ifPresent(h -> {
            sb.append("IP: ").append(h.getIp()).append("\n");
            sb.append("Device type: ").append(h.getDeviceType())
              .append(" (confidence: ").append(h.getConfidence()).append("%)\n");
            if (h.getManufacturer() != null) sb.append("Manufacturer: ").append(h.getManufacturer()).append("\n");
            if (h.getTtl() != null) sb.append("TTL: ").append(h.getTtl()).append("\n");
          });
    }

    return sb.toString().isBlank() ? "No classification data available." : sb.toString();
  }

  private String buildSuggestSystemPrompt() {
    return """
        You are a network analyst specialising in operational technology (OT), industrial control
        systems (ICS), and enterprise IT networks.
        Given classification signals for a network node, suggest a concise operational role label
        and a brief description. The role should reflect what this device likely *does* on the
        network (e.g. "SCADA Controller", "Water Pump PLC", "DNS Server", "Employee Laptop",
        "IP Camera").
        IMPORTANT: If the available signals are too sparse or generic to make a meaningful,
        specific assessment (e.g. only a MAC address with no apps, protocols, or manufacturer),
        you MUST return null for both fields rather than guessing.
        Respond ONLY with valid JSON in the format:
        {"roleLabel": "...", "roleDescription": "..."}
        If evidence is insufficient, respond with:
        {"roleLabel": null, "roleDescription": null}
        Do not add any other text outside the JSON.
        """;
  }

  private String buildSuggestUserPrompt(String entityType, String entityKey, String context) {
    return String.format("""
        ## Node Identity
        Entity type: %s
        Entity key: %s

        ## Classification Signals
        %s

        Suggest a short role label (3-6 words) and a one-sentence description.
        Only suggest if the signals provide meaningful, specific evidence.
        If the evidence is too sparse or generic, return null for both fields.
        Respond ONLY with valid JSON: {"roleLabel": "...", "roleDescription": "..."}
        """, entityType, entityKey, context);
  }

  private String extractJson(String content) {
    if (content == null || content.isBlank()) throw new RuntimeException("Empty LLM response");
    content = content.replaceAll("```json\\s*", "").replaceAll("```\\s*", "");
    int start = content.indexOf('{');
    int end = content.lastIndexOf('}');
    if (start >= 0 && end > start) return content.substring(start, end + 1);
    return content;
  }

  private NodeRoleDto toDto(NodeRoleEntity e) {
    return NodeRoleDto.builder()
        .entityType(e.getEntityType())
        .entityKey(e.getEntityKey())
        .roleLabel(e.getRoleLabel())
        .roleDescription(e.getRoleDescription())
        .llmSuggested(e.isLlmSuggested())
        .confirmedByHuman(e.isConfirmedByHuman())
        .createdAt(e.getCreatedAt())
        .updatedAt(e.getUpdatedAt())
        .build();
  }
}
