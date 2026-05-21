package com.lanturn.insights.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.lanturn.common.exception.ResourceNotFoundException;
import com.lanturn.config.LlmConfig;
import com.lanturn.insights.dto.GenerateInsightRequest;
import com.lanturn.insights.dto.NetworkInsightDto;
import com.lanturn.insights.dto.NetworkInsightDto.Anomaly;
import com.lanturn.insights.dto.NetworkInsightDto.Correlation;
import com.lanturn.insights.dto.NetworkInsightDto.NarrativeSection;
import com.lanturn.insights.entity.NodeRoleEntity;
import com.lanturn.insights.entity.SnapshotInsightEntity;
import com.lanturn.insights.repository.NetworkExternalEventRepository;
import com.lanturn.insights.repository.NodeRoleRepository;
import com.lanturn.insights.repository.SnapshotInsightRepository;
import com.lanturn.insights.entity.NetworkExternalEventEntity;
import com.lanturn.monitor.entity.NetworkChangeEventEntity;
import com.lanturn.monitor.entity.NetworkSnapshotEntity;
import com.lanturn.monitor.repository.NetworkChangeEventRepository;
import com.lanturn.monitor.repository.NetworkSnapshotRepository;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class SnapshotInsightService {

  private final SnapshotInsightRepository snapshotInsightRepository;
  private final NetworkSnapshotRepository snapshotRepository;
  private final NetworkChangeEventRepository changeEventRepository;
  private final NetworkExternalEventRepository externalEventRepository;
  private final NodeRoleRepository nodeRoleRepository;
  private final com.lanturn.story.service.LlmClient llmClient;
  private final LlmConfig llmConfig;
  private final ObjectMapper objectMapper;

  private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm");

  public Optional<NetworkInsightDto> getLatestInsight(UUID snapshotId) {
    return snapshotInsightRepository.findTopBySnapshotIdOrderByGeneratedAtDesc(snapshotId)
        .map(this::toDto);
  }

  // Not @Transactional: LLM call can be slow
  public NetworkInsightDto generateInsight(UUID networkId, UUID snapshotId, GenerateInsightRequest req) {
    log.info("Generating snapshot insight for snapshot: {}", snapshotId);

    NetworkSnapshotEntity snapshot = snapshotRepository.findById(snapshotId)
        .filter(s -> s.getNetwork().getId().equals(networkId))
        .orElseThrow(() -> new ResourceNotFoundException("Snapshot not found: " + snapshotId));

    // Load the snapshot's file eagerly (already in same transaction scope via repository)
    List<NetworkChangeEventEntity> changeEvents =
        changeEventRepository.findByToSnapshotIdOrderByDetectedAtDesc(snapshotId);

    // External events overlapping the snapshot's capture window (if timestamps available)
    List<NetworkExternalEventEntity> externalEvents;
    if (snapshot.getFile().getStartTime() != null && snapshot.getFile().getEndTime() != null) {
      externalEvents = externalEventRepository
          .findByNetworkIdAndEventTimeBetweenOrderByEventTimeAsc(
              networkId,
              snapshot.getFile().getStartTime(),
              snapshot.getFile().getEndTime());
    } else {
      externalEvents = externalEventRepository.findByNetworkIdOrderByEventTimeDesc(networkId);
    }

    // Batch-load node roles for entities appearing in change events
    Set<String> entityKeys = changeEvents.stream()
        .map(NetworkChangeEventEntity::getEntityKey)
        .collect(Collectors.toSet());
    List<String> allTypes = List.of("IP", "DEVICE", "APP", "PROTOCOL");
    Map<String, NodeRoleEntity> rolesByKey = nodeRoleRepository
        .findByEntityTypeInAndEntityKeyIn(allTypes, entityKeys)
        .stream()
        .collect(Collectors.toMap(NodeRoleEntity::getEntityKey, r -> r, (a, b) -> a));

    String audience = req != null && req.getAudience() != null ? req.getAudience() : "TECHNICAL";
    String focus    = req != null && req.getFocus()    != null ? req.getFocus()    : "SECURITY";

    String userPrompt = buildUserPrompt(snapshot, changeEvents, externalEvents, rolesByKey);
    String systemPrompt = buildSystemPrompt(audience, focus);

    SnapshotInsightEntity saved;
    try {
      String raw = llmClient.generateCompletion(systemPrompt, userPrompt);
      String json = extractJson(raw);
      saved = SnapshotInsightEntity.builder()
          .snapshot(snapshot)
          .modelUsed(llmConfig.getApi().getModel())
          .status("COMPLETED")
          .content(json)
          .audience(audience)
          .focus(focus)
          .build();
      snapshotInsightRepository.save(saved);
    } catch (Exception e) {
      log.error("Failed to generate snapshot insight for {}: {}", snapshotId, e.getMessage());
      saved = SnapshotInsightEntity.builder()
          .snapshot(snapshot)
          .modelUsed(llmConfig.getApi().getModel())
          .status("FAILED")
          .errorMessage(e.getMessage())
          .audience(audience)
          .focus(focus)
          .build();
      snapshotInsightRepository.save(saved);
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
          and change types verbatim. Target an analyst performing active network investigation.
          """;
    };

    String focusInstr = switch (focus) {
      case "OPERATIONAL" -> """
          Focus on what changed from a network operations perspective — new devices, topology shifts,
          and whether changes were expected given the operational context provided.
          Highlight unexpected changes and those with no corresponding external event.
          """;
      case "COMPLIANCE" -> """
          Focus on deviations from the defined baseline — which devices, bindings, protocols, or
          applications appeared that are not expected. Highlight how many change events have been
          reviewed vs unreviewed. Frame recommendations around documentation and audit trail completeness.
          """;
      default -> """
          Focus on security-relevant patterns — potential ARP spoofing, gateway changes, unexpected
          new devices, new protocols that could indicate lateral movement or exfiltration.
          Prioritise anomalies that have no external event explanation.
          """;
    };

    return """
        %s

        %s

        %s

        Rules:
        - Only reference events and roles provided. Do not invent facts.
        - Correlations must link a specific external event to a specific change event.
        - Anomalies are changes that cannot be explained by any external event or context provided.
        - Severity: LOW, MEDIUM, or HIGH.

        Respond ONLY with valid JSON:
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
      NetworkSnapshotEntity snapshot,
      List<NetworkChangeEventEntity> changeEvents,
      List<NetworkExternalEventEntity> externalEvents,
      Map<String, NodeRoleEntity> rolesByKey) {

    StringBuilder sb = new StringBuilder();

    // Snapshot header
    sb.append("## Snapshot\n");
    sb.append("File: ").append(snapshot.getFile().getFileName()).append("\n");
    sb.append("Order: ").append(snapshot.getSnapshotOrder() + 1).append("\n");
    if (snapshot.getFile().getStartTime() != null) {
      sb.append("Capture start: ").append(snapshot.getFile().getStartTime().format(FMT)).append("\n");
    }
    if (snapshot.getFile().getEndTime() != null) {
      sb.append("Capture end: ").append(snapshot.getFile().getEndTime().format(FMT)).append("\n");
    }
    if (snapshot.getFile().getPacketCount() != null) {
      sb.append("Packets: ").append(snapshot.getFile().getPacketCount()).append("\n");
    }

    // Analyst context
    if (snapshot.getContext() != null && !snapshot.getContext().isBlank()) {
      sb.append("\n## Analyst Context\n").append(snapshot.getContext()).append("\n");
    }
    if (snapshot.getNotes() != null && !snapshot.getNotes().isBlank()) {
      sb.append("\n## Analyst Notes\n").append(snapshot.getNotes()).append("\n");
    }

    // Device & IP Roles
    if (!rolesByKey.isEmpty()) {
      sb.append("\n## Device & IP Roles\n");
      rolesByKey.values().forEach(r -> {
        sb.append("- ").append(r.getEntityKey());
        if (r.getRoleLabel() != null) sb.append(": ").append(r.getRoleLabel());
        if (r.getRoleDescription() != null) sb.append(" — ").append(r.getRoleDescription());
        sb.append("\n");
      });
    }

    // Change events for this snapshot
    sb.append("\n## Change Events (vs previous snapshot)\n");
    if (changeEvents.isEmpty()) {
      sb.append("No changes detected for this snapshot.\n");
    } else {
      changeEvents.forEach(e -> {
        sb.append("- [").append(e.getSeverity()).append("] ")
            .append(e.getChangeType()).append(" — ").append(e.getEntityKey());
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

    // External events in capture window
    sb.append("\n## External Events (during capture window)\n");
    if (externalEvents.isEmpty()) {
      sb.append("None.\n");
    } else {
      externalEvents.forEach(e -> {
        sb.append("- ").append(e.getEventTime().format(FMT)).append(": ").append(e.getTitle());
        if (e.getDescription() != null) sb.append(" — ").append(e.getDescription());
        sb.append("\n");
      });
    }

    sb.append("\nRespond ONLY with valid JSON as specified in the system prompt.");
    return sb.toString();
  }

  private String formatValue(Map<String, Object> value) {
    if (value == null) return "—";
    return value.entrySet().stream()
        .map(e -> e.getKey() + "=" + e.getValue())
        .collect(Collectors.joining(", "));
  }

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
  private NetworkInsightDto toDto(SnapshotInsightEntity e) {
    NetworkInsightDto.NetworkInsightDtoBuilder builder = NetworkInsightDto.builder()
        .id(e.getId())
        .networkId(e.getSnapshot().getNetwork().getId())
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
        log.warn("Failed to parse snapshot insight content for {}: {}", e.getId(), ex.getMessage());
      }
    }
    return builder.build();
  }

  @SuppressWarnings("unchecked")
  private List<NarrativeSection> parseNarrativeSections(Object raw) {
    if (!(raw instanceof List)) return List.of();
    return ((List<Map<String, Object>>) raw).stream()
        .filter(m -> m.containsKey("title") && m.containsKey("content"))
        .map(m -> NarrativeSection.builder().title((String) m.get("title")).content((String) m.get("content")).build())
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
