package com.tracepcap.story.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracepcap.analysis.entity.AnalysisResultEntity;
import com.tracepcap.analysis.entity.ConversationEntity;
import com.tracepcap.analysis.repository.AnalysisResultRepository;
import com.tracepcap.analysis.repository.ConversationRepository;
import com.tracepcap.common.exception.ResourceNotFoundException;
import com.tracepcap.config.LlmConfig;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.repository.FileRepository;
import com.tracepcap.story.dto.*;
import com.tracepcap.story.entity.StoryEntity;
import com.tracepcap.story.repository.StoryRepository;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Service for generating and managing network traffic stories using LLM */
@Slf4j
@Service
@RequiredArgsConstructor
public class StoryService {

  private final StoryRepository storyRepository;
  private final FileRepository fileRepository;
  private final AnalysisResultRepository analysisResultRepository;
  private final ConversationRepository conversationRepository;
  private final LlmClient llmClient;
  private final LlmConfig llmConfig;
  private final ObjectMapper objectMapper;

  /**
   * Generate a story for a PCAP file using LLM
   *
   * @param fileId the file ID
   * @return generated story response
   */
  @Transactional
  public StoryResponse generateStory(UUID fileId) {
    log.info("Generating story for file: {}", fileId);

    // Delete any existing stories for this file so we always generate fresh
    storyRepository.deleteByFileId(fileId);

    // Verify file exists
    FileEntity file =
        fileRepository
            .findById(fileId)
            .orElseThrow(() -> new ResourceNotFoundException("File not found: " + fileId));

    // Get analysis results
    AnalysisResultEntity analysis =
        analysisResultRepository
            .findByFileId(fileId)
            .orElseThrow(
                () -> new ResourceNotFoundException("Analysis not found for file: " + fileId));

    // Get conversations
    List<ConversationEntity> conversations = conversationRepository.findByFileId(fileId);

    // Generate story ID upfront
    UUID storyId = UUID.randomUUID();
    LocalDateTime generatedAt = LocalDateTime.now();

    try {
      // Generate story content using LLM
      String storyContent = generateStoryContent(file, analysis, conversations);

      // Parse LLM response
      StoryResponse storyResponse = parseStoryContent(storyContent, storyId, fileId);

      // Create and save story entity with content
      StoryEntity story =
          StoryEntity.builder()
              .id(storyId)
              .fileId(fileId)
              .generatedAt(generatedAt)
              .status(StoryEntity.StoryStatus.COMPLETED)
              .modelUsed(llmConfig.getApi().getModel())
              .content(objectMapper.writeValueAsString(storyResponse))
              .build();

      storyRepository.save(story);

      log.info("Successfully generated story for file: {}", fileId);
      return storyResponse;

    } catch (Exception e) {
      log.error("Failed to generate story for file: {}", fileId, e);

      // Save failed story
      StoryEntity failedStory =
          StoryEntity.builder()
              .id(storyId)
              .fileId(fileId)
              .generatedAt(generatedAt)
              .status(StoryEntity.StoryStatus.FAILED)
              .modelUsed(llmConfig.getApi().getModel())
              .errorMessage(e.getMessage())
              .content("{}") // Empty JSON to satisfy NOT NULL constraint
              .build();

      storyRepository.save(failedStory);
      throw new RuntimeException("Failed to generate story: " + e.getMessage(), e);
    }
  }

  /**
   * Get an existing story by ID
   *
   * @param storyId the story ID
   * @return story response
   */
  public StoryResponse getStory(UUID storyId) {
    StoryEntity story =
        storyRepository
            .findById(storyId)
            .orElseThrow(() -> new ResourceNotFoundException("Story not found: " + storyId));

    try {
      StoryResponse response = objectMapper.readValue(story.getContent(), StoryResponse.class);
      return response;
    } catch (Exception e) {
      log.error("Failed to parse story content", e);
      throw new RuntimeException("Failed to parse story content: " + e.getMessage(), e);
    }
  }

  /** Generate story content using LLM */
  private String generateStoryContent(
      FileEntity file, AnalysisResultEntity analysis, List<ConversationEntity> conversations) {

    String systemPrompt = buildSystemPrompt();
    String userPrompt = buildUserPrompt(file, analysis, conversations);

    return llmClient.generateCompletion(systemPrompt, userPrompt);
  }

  /** Build system prompt for LLM */
  private String buildSystemPrompt() {
    return """
            You are a cybersecurity analyst expert specializing in network traffic analysis.
            Your task is to analyze PCAP file data and create a comprehensive, narrative story
            that explains what happened in the network traffic in a clear and engaging way.

            You must respond ONLY with valid JSON in the following format:
            {
              "narrative": [
                {
                  "title": "Summary",
                  "content": "A comprehensive summary of the network traffic...",
                  "type": "summary",
                  "relatedData": {
                    "packets": [],
                    "conversations": [],
                    "hosts": []
                  }
                }
              ],
              "highlights": [
                {
                  "id": "h1",
                  "type": "anomaly",
                  "title": "Unusual Traffic Pattern",
                  "description": "Description of the anomaly...",
                  "timestamp": 1234567890
                }
              ],
              "timeline": [
                {
                  "timestamp": 1234567890,
                  "title": "Connection Established",
                  "description": "Description of the event...",
                  "type": "normal",
                  "relatedData": {
                    "packets": [],
                    "conversations": []
                  }
                }
              ]
            }

            Narrative types: "summary", "detail", "anomaly", "conclusion"
            Highlight types: "anomaly", "insight", "warning", "info"
            Timeline event types: "normal", "suspicious", "critical"

            Focus on:
            - Clear, technical but accessible language
            - Identifying patterns, anomalies, and security concerns
            - Providing actionable insights
            - Creating a chronological narrative of events

            Security risk guidance:
            - Conversations tagged with nDPI security risks (shown as [RISKS: ...]) should be
              treated as the highest-priority findings in the story.
            - Each risk flag in the Security Alerts section must appear in at least one highlight
              (type "anomaly" for severe risks such as clear_text_credentials, suspicious_entropy,
              suspicious_dns_traffic, binary_application_transfer, possible_exploit_detected;
              type "warning" for certificate/policy issues such as self_signed_certificate,
              obsolete_tls_version, weak_tls_cipher) and one timeline event
              (type "critical" or "suspicious" accordingly).
            - Do NOT invent risks that are not listed in the data.
            """;
  }

  /**
   * Build user prompt with analysis data.
   *
   * <p>Data included in the prompt:
   * <ul>
   *   <li>File metadata (name, size, upload time)</li>
   *   <li>Traffic summary (packet count, bytes, duration, time range)</li>
   *   <li>Protocol breakdown (packet count, bytes, % per protocol)</li>
   *   <li>Top-N conversations by traffic volume, including app name and nDPI risk flags where detected</li>
   *   <li>Security Alerts section listing all conversations with at least one risk flag</li>
   * </ul>
   *
   * <p>Known limitations — data NOT available to the LLM:
   * <ul>
   *   <li>Packet-level payloads or raw bytes (not captured during analysis)</li>
   *   <li>Conversations beyond the configured cap (STORY_MAX_CONVERSATIONS)</li>
   *   <li>Application-layer content (HTTP bodies, DNS query names, TLS SNI, etc.)</li>
   * </ul>
   */
  /**
   * Build a TLS certificate label for a conversation, e.g.:
   * " [TLS: subject=CN=*.example.com, issuer=CN=Let's Encrypt, expires=2025/06/01 EXPIRED]"
   * Returns an empty string if no TLS cert data is available.
   */
  private String buildTlsCertLabel(ConversationEntity conv) {
    if (conv.getTlsIssuer() == null && conv.getTlsSubject() == null
        && conv.getTlsNotAfter() == null) {
      return "";
    }
    StringBuilder sb = new StringBuilder(" [TLS:");
    if (conv.getTlsSubject() != null) sb.append(" subject=").append(conv.getTlsSubject()).append(",");
    if (conv.getTlsIssuer() != null)  sb.append(" issuer=").append(conv.getTlsIssuer()).append(",");
    if (conv.getTlsNotAfter() != null) {
      boolean expired = conv.getTlsNotAfter().isBefore(LocalDateTime.now());
      sb.append(" expires=").append(conv.getTlsNotAfter().toString());
      if (expired) sb.append(" EXPIRED");
    }
    // trim trailing comma if present
    int last = sb.length() - 1;
    if (sb.charAt(last) == ',') sb.deleteCharAt(last);
    sb.append("]");
    return sb.toString();
  }

  private String buildUserPrompt(
      FileEntity file, AnalysisResultEntity analysis, List<ConversationEntity> conversations) {

    int maxConversations = llmConfig.getStory() != null
        ? llmConfig.getStory().getMaxConversations()
        : 20;

    StringBuilder prompt = new StringBuilder();
    prompt.append("Analyze this network traffic capture and create a comprehensive story:\n\n");

    prompt.append("## File Information\n");
    prompt.append(String.format("- Filename: %s\n", file.getFileName()));
    prompt.append(String.format("- File Size: %d bytes\n", file.getFileSize()));
    prompt.append(String.format("- Upload Time: %s\n\n", file.getUploadedAt()));

    prompt.append("## Traffic Summary\n");
    prompt.append(String.format("- Total Packets: %d\n", analysis.getPacketCount()));
    prompt.append(String.format("- Total Bytes: %d\n", analysis.getTotalBytes()));
    prompt.append(String.format("- Duration: %d ms\n", analysis.getDurationMs()));
    prompt.append(String.format("- Start Time: %s\n", analysis.getStartTime()));
    prompt.append(String.format("- End Time: %s\n\n", analysis.getEndTime()));

    // Protocol breakdown
    if (analysis.getProtocolStats() != null && !analysis.getProtocolStats().isEmpty()) {
      prompt.append("## Protocol Breakdown\n");
      analysis.getProtocolStats().forEach((protocol, statsObj) -> {
        if (statsObj instanceof Map) {
          @SuppressWarnings("unchecked")
          Map<String, Object> stats = (Map<String, Object>) statsObj;
          Object packets = stats.get("packetCount");
          Object bytes = stats.get("bytes");
          Object pct = stats.get("percentage");
          prompt.append(String.format("- %s: %s packets, %s bytes (%.1f%%)\n",
              protocol, packets, bytes,
              pct instanceof Number ? ((Number) pct).doubleValue() : 0.0));
        }
      });
      prompt.append("\n");
    }

    // Category distribution (nDPI traffic categories)
    Map<String, Long> catPackets = new java.util.TreeMap<>();
    conversations.stream()
        .filter(c -> c.getCategory() != null && !c.getCategory().isBlank())
        .forEach(c -> catPackets.merge(c.getCategory(),
            c.getPacketCount() != null ? c.getPacketCount() : 0L, Long::sum));
    if (!catPackets.isEmpty()) {
      prompt.append("## Traffic Category Breakdown\n");
      catPackets.forEach((cat, packets) ->
          prompt.append(String.format("- %s: %d packets\n", cat, packets)));
      prompt.append("\n");
    }

    // Top-N conversations sorted by traffic volume (most significant first)
    if (!conversations.isEmpty()) {
      List<ConversationEntity> sorted = conversations.stream()
          .sorted(Comparator.comparingLong(ConversationEntity::getTotalBytes).reversed())
          .collect(Collectors.toList());

      int shown = Math.min(maxConversations, sorted.size());
      prompt.append(String.format("## Top %d Conversations (by traffic volume)\n", shown));

      for (int i = 0; i < shown; i++) {
        ConversationEntity conv = sorted.get(i);
        String appLabel = (conv.getAppName() != null && !conv.getAppName().isBlank())
            ? " [" + conv.getAppName() + "]"
            : "";
        String catLabel = (conv.getCategory() != null && !conv.getCategory().isBlank())
            ? " [CAT: " + conv.getCategory() + "]"
            : "";
        String riskLabel = (conv.getFlowRisks() != null && conv.getFlowRisks().length > 0)
            ? " [RISKS: " + String.join(", ", conv.getFlowRisks()) + "]"
            : "";
        String tlsCertLabel = buildTlsCertLabel(conv);
        prompt.append(String.format(
            "%d. %s:%s <-> %s:%s (%s%s%s%s%s, %d packets, %d bytes)\n",
            i + 1,
            conv.getSrcIp(), conv.getSrcPort() != null ? conv.getSrcPort() : "*",
            conv.getDstIp(), conv.getDstPort() != null ? conv.getDstPort() : "*",
            conv.getProtocol(), appLabel, catLabel, riskLabel, tlsCertLabel,
            conv.getPacketCount(),
            conv.getTotalBytes()));
      }

      if (sorted.size() > maxConversations) {
        prompt.append(String.format(
            "... and %d more conversations not shown (increase STORY_MAX_CONVERSATIONS to include them).\n",
            sorted.size() - maxConversations));
      }
      prompt.append("\n");

      // Security alerts section — includes all at-risk conversations, even those outside top-N
      List<ConversationEntity> atRisk = conversations.stream()
          .filter(c -> c.getFlowRisks() != null && c.getFlowRisks().length > 0)
          .collect(Collectors.toList());
      if (!atRisk.isEmpty()) {
        prompt.append(String.format("## Security Alerts (%d conversations with nDPI risk flags)\n",
            atRisk.size()));
        for (ConversationEntity conv : atRisk) {
          String appLabel = (conv.getAppName() != null && !conv.getAppName().isBlank())
              ? " [" + conv.getAppName() + "]"
              : "";
          prompt.append(String.format(
              "- %s:%s <-> %s:%s (%s%s): %s\n",
              conv.getSrcIp(), conv.getSrcPort() != null ? conv.getSrcPort() : "*",
              conv.getDstIp(), conv.getDstPort() != null ? conv.getDstPort() : "*",
              conv.getProtocol(), appLabel,
              String.join(", ", conv.getFlowRisks())));
        }
        prompt.append("\n");
      }
    }

    prompt.append("## Analysis Limitations\n");
    prompt.append("The following data was NOT available during this analysis — do not infer or hallucinate details about them:\n");
    prompt.append("- Packet payloads or raw bytes (not captured)\n");
    prompt.append("- Application-layer content (HTTP bodies, DNS query names, etc.)\n");
    prompt.append("- Any conversations beyond those listed above\n\n");

    prompt.append("Generate a detailed story analyzing this network traffic. ");
    prompt.append("Include narrative sections, highlights of interesting findings, ");
    prompt.append("and a timeline of key events. Respond ONLY with valid JSON.");

    return prompt.toString();
  }

  /** Parse LLM response into StoryResponse */
  private StoryResponse parseStoryContent(String content, UUID storyId, UUID fileId) {
    try {
      // Extract JSON from response (in case LLM adds extra text)
      String jsonContent = extractJson(content);

      // Parse JSON
      Map<String, Object> data = objectMapper.readValue(jsonContent, new TypeReference<>() {});

      // Parse narrative sections (required)
      List<NarrativeSection> narrative = parseNarrativeSections(data.get("narrative"));
      if (narrative.isEmpty()) {
        log.warn("No narrative sections found in LLM response, adding default section");
        narrative.add(
            NarrativeSection.builder()
                .title("Analysis Summary")
                .content(
                    "Unable to generate detailed narrative. Please try regenerating the story.")
                .type(NarrativeSection.SectionType.summary)
                .relatedData(
                    NarrativeSection.RelatedData.builder()
                        .packets(new ArrayList<>())
                        .conversations(new ArrayList<>())
                        .hosts(new ArrayList<>())
                        .build())
                .build());
      }

      // Parse highlights (optional)
      List<Highlight> highlights = parseHighlights(data.get("highlights"));

      // Parse timeline (optional)
      List<StoryTimelineEvent> timeline = parseTimeline(data.get("timeline"));

      log.info(
          "Successfully parsed story: {} narrative sections, {} highlights, {} timeline events",
          narrative.size(),
          highlights.size(),
          timeline.size());

      return StoryResponse.builder()
          .id(storyId.toString())
          .fileId(fileId.toString())
          .generatedAt(System.currentTimeMillis())
          .narrative(narrative)
          .highlights(highlights)
          .timeline(timeline)
          .build();

    } catch (Exception e) {
      log.error("Failed to parse LLM response: {}", e.getMessage(), e);
      log.debug("LLM response content: {}", content);
      throw new RuntimeException("Failed to parse LLM response: " + e.getMessage(), e);
    }
  }

  /** Extract JSON from LLM response */
  private String extractJson(String content) {
    if (content == null || content.trim().isEmpty()) {
      throw new RuntimeException("Empty LLM response");
    }

    // Remove markdown code blocks if present
    content = content.replaceAll("```json\\s*", "").replaceAll("```\\s*", "");

    // Find first { and last }
    int start = content.indexOf('{');
    int end = content.lastIndexOf('}');

    if (start >= 0 && end > start) {
      String json = content.substring(start, end + 1);
      log.debug("Extracted JSON from LLM response, length: {}", json.length());
      return json;
    }

    log.warn("Could not extract JSON from LLM response, using raw content");
    return content;
  }

  /** Parse narrative sections from JSON */
  @SuppressWarnings("unchecked")
  private List<NarrativeSection> parseNarrativeSections(Object data) {
    if (data == null) return new ArrayList<>();

    try {
      List<Map<String, Object>> sections = (List<Map<String, Object>>) data;
      return sections.stream()
          .filter(
              section ->
                  section != null && section.get("title") != null && section.get("content") != null)
          .map(
              section -> {
                Map<String, Object> relatedData =
                    (Map<String, Object>) section.getOrDefault("relatedData", new HashMap<>());

                return NarrativeSection.builder()
                    .title((String) section.get("title"))
                    .content((String) section.get("content"))
                    .type(parseSectionType((String) section.getOrDefault("type", "detail")))
                    .relatedData(
                        NarrativeSection.RelatedData.builder()
                            .packets(convertToStringList(relatedData.get("packets")))
                            .conversations(convertToStringList(relatedData.get("conversations")))
                            .hosts(convertToStringList(relatedData.get("hosts")))
                            .build())
                    .build();
              })
          .collect(Collectors.toList());
    } catch (Exception e) {
      log.error("Error parsing narrative sections", e);
      return new ArrayList<>();
    }
  }

  /** Parse highlights from JSON */
  @SuppressWarnings("unchecked")
  private List<Highlight> parseHighlights(Object data) {
    if (data == null) return new ArrayList<>();

    try {
      List<Map<String, Object>> highlights = (List<Map<String, Object>>) data;
      return highlights.stream()
          .filter(h -> h != null && h.get("title") != null)
          .map(
              h -> {
                Object timestamp = h.get("timestamp");
                Long ts = null;
                try {
                  ts = timestamp != null ? ((Number) timestamp).longValue() : null;
                } catch (Exception e) {
                  log.warn("Invalid timestamp value: {}", timestamp);
                }

                String id = (String) h.get("id");
                if (id == null) {
                  id = "h" + UUID.randomUUID().toString().substring(0, 8);
                }

                return Highlight.builder()
                    .id(id)
                    .type(parseHighlightType((String) h.getOrDefault("type", "info")))
                    .title((String) h.get("title"))
                    .description((String) h.getOrDefault("description", ""))
                    .timestamp(ts)
                    .build();
              })
          .collect(Collectors.toList());
    } catch (Exception e) {
      log.error("Error parsing highlights", e);
      return new ArrayList<>();
    }
  }

  /** Parse timeline events from JSON */
  @SuppressWarnings("unchecked")
  private List<StoryTimelineEvent> parseTimeline(Object data) {
    if (data == null) return new ArrayList<>();

    try {
      List<Map<String, Object>> events = (List<Map<String, Object>>) data;
      return events.stream()
          .filter(event -> event != null && event.get("title") != null)
          .map(
              event -> {
                Map<String, Object> relatedData =
                    (Map<String, Object>) event.getOrDefault("relatedData", new HashMap<>());
                Object timestamp = event.get("timestamp");

                Long ts = null;
                try {
                  ts = timestamp != null ? ((Number) timestamp).longValue() : null;
                } catch (Exception e) {
                  log.warn("Invalid timestamp value: {}", timestamp);
                }

                return StoryTimelineEvent.builder()
                    .timestamp(ts)
                    .title((String) event.get("title"))
                    .description((String) event.getOrDefault("description", ""))
                    .type(parseEventType((String) event.getOrDefault("type", "normal")))
                    .relatedData(
                        StoryTimelineEvent.RelatedData.builder()
                            .packets(convertToStringList(relatedData.get("packets")))
                            .conversations(convertToStringList(relatedData.get("conversations")))
                            .build())
                    .build();
              })
          .collect(Collectors.toList());
    } catch (Exception e) {
      log.error("Error parsing timeline events", e);
      return new ArrayList<>();
    }
  }

  /** Convert various types to string list (handles both strings and objects) */
  @SuppressWarnings("unchecked")
  private List<String> convertToStringList(Object data) {
    if (data == null) {
      return new ArrayList<>();
    }

    if (!(data instanceof List)) {
      return new ArrayList<>();
    }

    List<?> list = (List<?>) data;
    return list.stream()
        .map(
            item -> {
              if (item instanceof String) {
                return (String) item;
              } else if (item instanceof Map) {
                // If it's a map, try to get an "id" or convert to string
                Map<String, Object> map = (Map<String, Object>) item;
                return map.getOrDefault("id", item.toString()).toString();
              } else {
                return item.toString();
              }
            })
        .collect(Collectors.toList());
  }

  /** Safely parse SectionType enum with case-insensitive matching and fallback */
  private NarrativeSection.SectionType parseSectionType(String type) {
    if (type == null || type.trim().isEmpty()) {
      return NarrativeSection.SectionType.detail;
    }

    try {
      return NarrativeSection.SectionType.valueOf(type.toLowerCase().trim());
    } catch (IllegalArgumentException e) {
      log.warn("Invalid section type '{}', using default 'detail'", type);
      return NarrativeSection.SectionType.detail;
    }
  }

  /** Safely parse HighlightType enum with case-insensitive matching and fallback */
  private Highlight.HighlightType parseHighlightType(String type) {
    if (type == null || type.trim().isEmpty()) {
      return Highlight.HighlightType.info;
    }

    try {
      return Highlight.HighlightType.valueOf(type.toLowerCase().trim());
    } catch (IllegalArgumentException e) {
      log.warn("Invalid highlight type '{}', using default 'info'", type);
      return Highlight.HighlightType.info;
    }
  }

  /** Safely parse EventType enum with case-insensitive matching and fallback */
  private StoryTimelineEvent.EventType parseEventType(String type) {
    if (type == null || type.trim().isEmpty()) {
      return StoryTimelineEvent.EventType.normal;
    }

    try {
      return StoryTimelineEvent.EventType.valueOf(type.toLowerCase().trim());
    } catch (IllegalArgumentException e) {
      log.warn("Invalid event type '{}', using default 'normal'", type);
      return StoryTimelineEvent.EventType.normal;
    }
  }
}
