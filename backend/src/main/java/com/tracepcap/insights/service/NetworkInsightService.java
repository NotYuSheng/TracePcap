package com.tracepcap.insights.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracepcap.common.exception.ResourceNotFoundException;
import com.tracepcap.config.LlmConfig;
import com.tracepcap.insights.dto.GenerateInsightRequest;
import com.tracepcap.insights.dto.NetworkInsightDto;
import com.tracepcap.insights.dto.NetworkInsightDto.Anomaly;
import com.tracepcap.insights.dto.NetworkInsightDto.Correlation;
import com.tracepcap.insights.dto.NetworkInsightDto.NarrativeSection;
import com.tracepcap.insights.entity.NetworkAnnotationEntity;
import com.tracepcap.insights.entity.NetworkExternalEventEntity;
import com.tracepcap.insights.entity.NetworkInsightEntity;
import com.tracepcap.insights.entity.NodeRoleEntity;
import com.tracepcap.insights.repository.NetworkAnnotationRepository;
import com.tracepcap.insights.repository.NetworkExternalEventRepository;
import com.tracepcap.insights.repository.NetworkInsightRepository;
import com.tracepcap.insights.repository.NodeRoleRepository;
import com.tracepcap.monitor.entity.NetworkChangeEventEntity;
import com.tracepcap.monitor.entity.NetworkEntity;
import com.tracepcap.monitor.entity.NetworkSnapshotEntity;
import com.tracepcap.monitor.repository.NetworkChangeEventRepository;
import com.tracepcap.monitor.repository.NetworkRepository;
import com.tracepcap.monitor.repository.NetworkSnapshotRepository;
import com.tracepcap.notes.entity.EntityNoteEntity;
import com.tracepcap.notes.repository.EntityNoteRepository;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class NetworkInsightService {

  private final NetworkInsightRepository insightRepository;
  private final NetworkRepository networkRepository;
  private final NetworkSnapshotRepository snapshotRepository;
  private final NetworkChangeEventRepository changeEventRepository;
  private final NetworkExternalEventRepository externalEventRepository;
  private final NetworkAnnotationRepository annotationRepository;
  private final NodeRoleRepository nodeRoleRepository;
  private final EntityNoteRepository entityNoteRepository;
  private final com.tracepcap.story.service.LlmClient llmClient;
  private final LlmConfig llmConfig;
  private final ObjectMapper objectMapper;

  private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm");

  public Optional<NetworkInsightDto> getLatestInsight(UUID networkId) {
    return insightRepository.findTopByNetworkIdOrderByGeneratedAtDesc(networkId)
        .map(this::toDto);
  }

  public boolean hasInsights(UUID networkId) {
    return insightRepository.existsByNetworkId(networkId);
  }

  // Not @Transactional: LLM call can take minutes
  public NetworkInsightDto generateInsights(UUID networkId, GenerateInsightRequest req) {
    log.info("Generating insights for network: {}", networkId);

    NetworkEntity network = networkRepository.findById(networkId)
        .orElseThrow(() -> new ResourceNotFoundException("Network not found: " + networkId));

    List<NetworkSnapshotEntity> snapshots = snapshotRepository.findByNetworkIdWithFileOrderBySnapshotOrderAsc(networkId);
    List<NetworkChangeEventEntity> changeEvents = changeEventRepository.findByNetworkIdOrderByDetectedAtDesc(networkId);
    List<NetworkExternalEventEntity> externalEvents = externalEventRepository.findByNetworkIdOrderByEventTimeDesc(networkId);
    List<NetworkAnnotationEntity> annotations = annotationRepository.findByNetworkIdOrderByCreatedAtDesc(networkId)
        .stream().limit(10).collect(Collectors.toList());

    // Collect entity keys that appear in change events to batch-load roles
    Set<String> entityKeys = changeEvents.stream()
        .map(NetworkChangeEventEntity::getEntityKey)
        .collect(Collectors.toSet());
    List<String> allTypes = List.of("IP", "DEVICE", "APP", "PROTOCOL");
    // Load all confirmed/suggested roles (not just change-event entities) for richer context
    Map<String, NodeRoleEntity> rolesByKey = nodeRoleRepository
        .findAll()
        .stream()
        .collect(Collectors.toMap(NodeRoleEntity::getEntityKey, r -> r, (a, b) -> a));

    // Load entity notes for all entities that appear in change events
    Map<String, String> entityNotesByKey = entityNoteRepository
        .findByEntityKeyIn(entityKeys)
        .stream()
        .collect(Collectors.toMap(EntityNoteEntity::getEntityKey, EntityNoteEntity::getNote, (a, b) -> a));

    String audience = req != null && req.getAudience() != null ? req.getAudience() : "TECHNICAL";
    String focus    = req != null && req.getFocus()    != null ? req.getFocus()    : "SECURITY";

    String systemPrompt = buildSystemPrompt(audience, focus);
    String userPrompt = buildUserPrompt(network, snapshots, changeEvents, externalEvents, annotations, rolesByKey, entityNotesByKey);

    NetworkInsightEntity saved;
    try {
      String raw = llmClient.generateCompletion(systemPrompt, userPrompt);
      String json = extractJson(raw);

      // Persist raw JSON content
      saved = NetworkInsightEntity.builder()
          .network(network)
          .modelUsed(llmConfig.getApi().getModel())
          .status("COMPLETED")
          .content(json)
          .audience(audience)
          .focus(focus)
          .build();
      insightRepository.save(saved);
      log.info("Saved insight for network: {}", networkId);
    } catch (Exception e) {
      log.error("Failed to generate insight for network {}: {}", networkId, e.getMessage());
      saved = NetworkInsightEntity.builder()
          .network(network)
          .modelUsed(llmConfig.getApi().getModel())
          .status("FAILED")
          .errorMessage(e.getMessage())
          .audience(audience)
          .focus(focus)
          .build();
      insightRepository.save(saved);
      return toDto(saved);
    }

    return toDto(saved);
  }

  // ── Prompt construction ───────────────────────────────────────────────────

  private String buildSystemPrompt(String audience, String focus) {
    String role = switch (audience) {
      case "EXECUTIVE" -> "You are a senior cybersecurity advisor preparing a briefing for executive leadership.";
      case "OT"        -> "You are an operational technology (OT) and industrial control systems (ICS) security specialist.";
      default          -> "You are an expert network and OT security analyst.";
    };

    String audienceInstr = switch (audience) {
      case "EXECUTIVE" -> """
          Write for a non-technical executive audience. Avoid raw protocol names, MAC addresses,
          and technical identifiers — instead translate them into business impact language.
          Keep language plain, concise, and actionable. Frame findings around risk and business continuity.
          """;
      case "OT" -> """
          Frame all findings around operational impact on industrial systems — PLCs, HMIs, historians,
          SCADA controllers, and field devices. Highlight any changes that could affect process
          availability, safety integrity, or the Purdue model zone boundaries.
          Use OT/ICS terminology where appropriate.
          """;
      default -> """
          Use precise technical terminology: include IP addresses, MAC addresses, protocol names,
          ASNs, and change types verbatim. Target an analyst performing active network investigation.
          """;
    };

    String focusInstr = switch (focus) {
      case "OPERATIONAL" -> """
          Focus on what changed from a network operations perspective — new devices, topology shifts,
          bandwidth anomalies, and whether changes were expected given the operational context provided.
          Highlight unexpected changes and those with no corresponding external event.
          """;
      case "COMPLIANCE" -> """
          Focus on deviations from the defined baseline — which devices, bindings, protocols, or
          applications appeared that are not in the baseline definitions. Highlight how many change
          events have been reviewed vs unreviewed. Frame recommendations around documentation and
          audit trail completeness.
          """;
      default -> """
          Focus on security-relevant patterns — potential ARP spoofing, gateway changes, unexpected
          new devices, new protocols or applications that could indicate lateral movement or
          exfiltration. Prioritise anomalies that have no external event explanation.
          """;
    };

    return """
        %s

        %s

        %s

        Rules:
        - Only reference change events, roles, and external events provided — do not invent facts.
        - Correlations must link a specific external event to a specific change event.
        - Keep the summary concise (2-4 sentences).
        - Anomalies are changes that cannot be explained by any external event or expected behaviour.
        - Severity for anomalies: LOW, MEDIUM, or HIGH.

        Respond ONLY with valid JSON matching this schema exactly:
        {
          "summary": "string",
          "narrativeSections": [{"title": "string", "content": "string"}],
          "anomalies": [{"title": "string", "description": "string", "severity": "LOW|MEDIUM|HIGH"}],
          "correlations": [{"externalEvent": "string", "networkChange": "string", "explanation": "string"}],
          "recommendations": ["string"]
        }
        """.formatted(role.strip(), audienceInstr.strip(), focusInstr.strip());
  }

  private String buildUserPrompt(
      NetworkEntity network,
      List<NetworkSnapshotEntity> snapshots,
      List<NetworkChangeEventEntity> changeEvents,
      List<NetworkExternalEventEntity> externalEvents,
      List<NetworkAnnotationEntity> annotations,
      Map<String, NodeRoleEntity> rolesByKey,
      Map<String, String> entityNotesByKey) {

    StringBuilder sb = new StringBuilder();

    // Network
    sb.append("## Network\n");
    sb.append("Name: ").append(network.getName()).append("\n");
    if (network.getDescription() != null && !network.getDescription().isBlank()) {
      sb.append("Description: ").append(network.getDescription()).append("\n");
    }
    sb.append("\n");

    // Snapshots
    sb.append("## Snapshots (chronological)\n");
    if (snapshots.isEmpty()) {
      sb.append("No snapshots.\n");
    } else {
      snapshots.forEach(s -> {
        sb.append("- ").append(s.getSnapshotOrder() + 1).append(". ")
          .append(s.getFile().getFileName());
        if (s.getFile().getStartTime() != null) {
          sb.append(" [").append(s.getFile().getStartTime().format(FMT)).append("]");
        }
        if (s.getFile().getPacketCount() != null) {
          sb.append(" — ").append(s.getFile().getPacketCount()).append(" packets");
        }
        if (s.getContext() != null && !s.getContext().isBlank()) {
          sb.append("\n  Context: ").append(s.getContext());
        }
        if (s.getNotes() != null && !s.getNotes().isBlank()) {
          sb.append("\n  Notes: ").append(s.getNotes());
        }
        sb.append("\n");
      });
    }
    sb.append("\n");

    // Device & IP Roles (only entities that appear in change events)
    if (!rolesByKey.isEmpty()) {
      sb.append("## Device & IP Roles\n");
      rolesByKey.values().forEach(r -> {
        sb.append("- ").append(r.getEntityKey());
        if (r.getRoleLabel() != null) sb.append(": ").append(r.getRoleLabel());
        if (r.getRoleDescription() != null) sb.append(" — ").append(r.getRoleDescription());
        if (r.isLlmSuggested() && !r.isConfirmedByHuman()) sb.append(" [AI-suggested]");
        sb.append("\n");
      });
      sb.append("\n");
    }

    // Change Events (up to 50, most recent)
    sb.append("## Change Events\n");
    if (changeEvents.isEmpty()) {
      sb.append("No change events detected.\n");
    } else {
      changeEvents.stream().limit(50).forEach(e -> {
        sb.append("- [").append(e.getSeverity()).append("] ")
          .append(e.getChangeType()).append(" — ").append(e.getEntityKey());
        if (e.getDetectedAt() != null) sb.append(" at ").append(e.getDetectedAt().format(FMT));
        if (e.getOldValue() != null && e.getNewValue() != null) {
          sb.append(" (was: ").append(formatValue(e.getOldValue()))
            .append(", now: ").append(formatValue(e.getNewValue())).append(")");
        }
        if (e.isReviewed() && e.getNotes() != null) {
          sb.append(" [reviewed: ").append(e.getNotes()).append("]");
        }
        sb.append("\n");
      });
    }
    sb.append("\n");

    // External Events
    sb.append("## External Events\n");
    if (externalEvents.isEmpty()) {
      sb.append("No external events recorded.\n");
    } else {
      externalEvents.forEach(e -> {
        sb.append("- ").append(e.getEventTime().format(FMT)).append(": ").append(e.getTitle());
        if (e.getDescription() != null) sb.append(" — ").append(e.getDescription());
        sb.append("\n");
      });
    }
    sb.append("\n");

    // Entity Notes (analyst notes on specific devices/IPs/protocols)
    if (!entityNotesByKey.isEmpty()) {
      sb.append("## Analyst Notes on Specific Entities\n");
      entityNotesByKey.forEach((key, note) -> {
        sb.append("- ").append(key).append(": ").append(note).append("\n");
      });
      sb.append("\n");
    }

    // Prior Analyst Annotations
    if (!annotations.isEmpty()) {
      sb.append("## Prior Analyst Annotations (most recent first)\n");
      annotations.forEach(a -> {
        sb.append("- [").append(a.getCreatedAt().format(FMT)).append("] ").append(a.getBody()).append("\n");
      });
      sb.append("\n");
    }

    sb.append("Respond ONLY with valid JSON as specified in the system prompt.");
    return sb.toString();
  }

  private String formatValue(Map<String, Object> value) {
    if (value == null) return "—";
    return value.entrySet().stream()
        .map(e -> e.getKey() + "=" + e.getValue())
        .collect(Collectors.joining(", "));
  }

  // ── JSON extraction (mirrors StoryService) ────────────────────────────────

  private String extractJson(String content) {
    if (content == null || content.isBlank()) throw new RuntimeException("Empty LLM response");
    content = content.replaceAll("```json\\s*", "").replaceAll("```\\s*", "");
    int start = content.indexOf('{');
    int end = content.lastIndexOf('}');
    if (start >= 0 && end > start) {
      String json = content.substring(start, end + 1);
      json = json.replaceAll("(?m)^(\\s*)//[^\n\r]*", "$1").replaceAll(",\\s*//[^\n\r]*", ",");
      return json;
    }
    return content;
  }

  // ── DTO mapping ───────────────────────────────────────────────────────────

  @SuppressWarnings("unchecked")
  private NetworkInsightDto toDto(NetworkInsightEntity e) {
    NetworkInsightDto.NetworkInsightDtoBuilder builder = NetworkInsightDto.builder()
        .id(e.getId())
        .networkId(e.getNetwork().getId())
        .generatedAt(e.getGeneratedAt())
        .modelUsed(e.getModelUsed())
        .status(e.getStatus())
        .errorMessage(e.getErrorMessage())
        .audience(e.getAudience())
        .focus(e.getFocus());

    if ("COMPLETED".equals(e.getStatus()) && e.getContent() != null) {
      try {
        Map<String, Object> data = objectMapper.readValue(e.getContent(), new TypeReference<>() {});
        builder.summary((String) data.get("summary"));
        builder.narrativeSections(parseNarrativeSections(data.get("narrativeSections")));
        builder.anomalies(parseAnomalies(data.get("anomalies")));
        builder.correlations(parseCorrelations(data.get("correlations")));
        builder.recommendations(parseRecommendations(data.get("recommendations")));
      } catch (Exception ex) {
        log.warn("Failed to parse insight content for {}: {}", e.getId(), ex.getMessage());
      }
    }

    return builder.build();
  }

  @SuppressWarnings("unchecked")
  private List<NarrativeSection> parseNarrativeSections(Object raw) {
    if (!(raw instanceof List)) return List.of();
    return ((List<Map<String, Object>>) raw).stream()
        .filter(m -> m.containsKey("title") && m.containsKey("content"))
        .map(m -> NarrativeSection.builder()
            .title((String) m.get("title"))
            .content((String) m.get("content"))
            .build())
        .collect(Collectors.toList());
  }

  @SuppressWarnings("unchecked")
  private List<Anomaly> parseAnomalies(Object raw) {
    if (!(raw instanceof List)) return List.of();
    return ((List<Map<String, Object>>) raw).stream()
        .filter(m -> m.containsKey("title"))
        .map(m -> Anomaly.builder()
            .title((String) m.get("title"))
            .description((String) m.getOrDefault("description", ""))
            .severity((String) m.getOrDefault("severity", "LOW"))
            .build())
        .collect(Collectors.toList());
  }

  @SuppressWarnings("unchecked")
  private List<Correlation> parseCorrelations(Object raw) {
    if (!(raw instanceof List)) return List.of();
    return ((List<Map<String, Object>>) raw).stream()
        .filter(m -> m.containsKey("externalEvent"))
        .map(m -> Correlation.builder()
            .externalEvent((String) m.get("externalEvent"))
            .networkChange((String) m.getOrDefault("networkChange", ""))
            .explanation((String) m.getOrDefault("explanation", ""))
            .build())
        .collect(Collectors.toList());
  }

  @SuppressWarnings("unchecked")
  private List<String> parseRecommendations(Object raw) {
    if (!(raw instanceof List)) return List.of();
    return ((List<Object>) raw).stream()
        .filter(Objects::nonNull)
        .map(Object::toString)
        .collect(Collectors.toList());
  }
}
