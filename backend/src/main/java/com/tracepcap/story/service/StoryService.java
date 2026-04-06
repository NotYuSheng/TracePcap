package com.tracepcap.story.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracepcap.analysis.entity.AnalysisResultEntity;
import com.tracepcap.analysis.entity.ConversationEntity;
import com.tracepcap.analysis.repository.AnalysisResultRepository;
import com.tracepcap.analysis.repository.ConversationRepository;
import com.tracepcap.analysis.service.GeoIpService;
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
import org.springframework.data.domain.PageRequest;
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
  private final GeoIpService geoIpService;

  /**
   * Generate a story for a PCAP file using LLM
   *
   * @param fileId the file ID
   * @return generated story response
   */
  @Transactional
  public StoryResponse generateStory(UUID fileId, String additionalContext) {
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

    // Generate story ID upfront
    UUID storyId = UUID.randomUUID();
    LocalDateTime generatedAt = LocalDateTime.now();

    try {
      // Generate story content using LLM
      String storyContent = generateStoryContent(file, analysis, additionalContext);

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
      return objectMapper.readValue(story.getContent(), StoryResponse.class);
    } catch (Exception e) {
      log.error("Failed to parse story content", e);
      throw new RuntimeException("Failed to parse story content: " + e.getMessage(), e);
    }
  }

  /**
   * Get the latest completed story for a file, if one exists
   *
   * @param fileId the file ID
   * @return story response, or empty if none
   */
  public Optional<StoryResponse> getStoryByFileId(UUID fileId) {
    return storyRepository
        .findFirstByFileIdOrderByGeneratedAtDesc(fileId)
        .filter(story -> story.getStatus() == StoryEntity.StoryStatus.COMPLETED)
        .map(
            story -> {
              try {
                return objectMapper.readValue(story.getContent(), StoryResponse.class);
              } catch (Exception e) {
                log.error("Failed to parse story content for file: {}", fileId, e);
                throw new RuntimeException("Failed to parse story content for file: " + fileId, e);
              }
            });
  }

  /**
   * Answer a question about an existing story using the LLM
   *
   * @param storyId the story ID
   * @param question the user's question
   * @return the LLM's answer
   */
  public StoryAnswerResponse askQuestion(
      UUID storyId, String question, List<StoryQuestionRequest.HistoryEntry> history) {
    StoryEntity story =
        storyRepository
            .findById(storyId)
            .orElseThrow(() -> new ResourceNotFoundException("Story not found: " + storyId));

    if (story.getStatus() != StoryEntity.StoryStatus.COMPLETED) {
      throw new IllegalStateException("Story is not in a completed state");
    }

    String systemPrompt =
        """
        You are a cybersecurity analyst expert. You have already generated a network traffic
        analysis story for a PCAP file. The story is provided to you as structured JSON below.

        Answer the user's question concisely and accurately, drawing only from the story data
        provided. If the answer cannot be determined from the available data, say so clearly.
        Do NOT invent details that are not present in the story.

        You must respond ONLY with valid JSON in this exact format:
        {
          "answer": "your plain-text answer here",
          "followUpQuestions": [
            "A specific follow-up question based on your answer",
            "Another relevant follow-up question",
            "A third follow-up question"
          ]
        }

        The followUpQuestions must be 3 short, specific questions an analyst would naturally
        ask next given your answer and the story data. Tailor them to the actual findings.
        """;

    StringBuilder userPrompt = new StringBuilder();
    userPrompt.append("## Story Data\n").append(story.getContent()).append("\n\n");

    if (history != null && !history.isEmpty()) {
      userPrompt.append("## Conversation History\n");
      for (var entry : history) {
        String role = "assistant".equals(entry.getRole()) ? "Analyst" : "User";
        userPrompt.append(role).append(": ").append(entry.getText()).append("\n\n");
      }
    }

    userPrompt.append("## Current Question\n").append(question);

    log.info("Answering question for story: {}", storyId);
    String raw = llmClient.generateCompletion(systemPrompt, userPrompt.toString());
    return parseAnswerResponse(raw);
  }

  /** Parse the LLM Q&A response into answer + follow-up questions */
  private StoryAnswerResponse parseAnswerResponse(String content) {
    try {
      String json = extractJson(content);
      Map<String, Object> data = objectMapper.readValue(json, new TypeReference<>() {});
      String answer = (String) data.getOrDefault("answer", content);
      List<String> followUps = parseSuggestedQuestions(data.get("followUpQuestions"));
      return new StoryAnswerResponse(answer, followUps);
    } catch (Exception e) {
      log.warn("Failed to parse Q&A JSON response, returning raw text: {}", e.getMessage());
      return new StoryAnswerResponse(content, new ArrayList<>());
    }
  }

  /** Generate story content using LLM */
  private String generateStoryContent(
      FileEntity file, AnalysisResultEntity analysis, String additionalContext) {
    String systemPrompt = buildSystemPrompt();
    String userPrompt = buildUserPrompt(file, analysis, additionalContext);
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
              ],
              "suggestedQuestions": [
                "Which host generated the most traffic, and what was it doing?",
                "Are there any signs of data exfiltration in this capture?",
                "What is the significance of the TLS certificate anomalies found?"
              ]
            }

            Narrative types: "summary", "detail", "anomaly", "conclusion"
            Highlight types: "anomaly", "insight", "warning", "info"
            Timeline event types: "normal", "suspicious", "critical"
            suggestedQuestions: exactly 3 short, specific follow-up questions a analyst might
            want to ask about THIS capture — tailored to the actual findings, not generic.

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
   *
   * <ul>
   *   <li>File metadata (name, size, upload time)
   *   <li>Traffic summary (packet count, bytes, duration, time range)
   *   <li>Protocol breakdown (packet count, bytes, % per protocol)
   *   <li>Top-N conversations by traffic volume, including app name and nDPI risk flags where
   *       detected
   *   <li>Security Alerts section listing all conversations with at least one risk flag
   * </ul>
   *
   * <p>Known limitations — data NOT available to the LLM:
   *
   * <ul>
   *   <li>Packet-level payloads or raw bytes (not captured during analysis)
   *   <li>Conversations beyond the configured cap (STORY_MAX_CONVERSATIONS)
   *   <li>Application-layer content (HTTP bodies, DNS query names, TLS SNI, etc.)
   * </ul>
   */
  /**
   * Build a TLS certificate label for a conversation, e.g.: " [TLS: subject=CN=*.example.com,
   * issuer=CN=Let's Encrypt, expires=2025/06/01 EXPIRED]" Returns an empty string if no TLS cert
   * data is available.
   */
  /**
   * Builds a geo label for a conversation, e.g. " [SG/AS9506 Singtel -> US/AS15169 Google LLC]".
   * Only external IPs (those present in geoMap) are annotated; private IPs are shown as "private".
   * Returns an empty string if neither endpoint has geo data.
   */
  private String buildGeoLabel(
      String srcIp, String dstIp, Map<String, GeoIpService.GeoResult> geoMap) {
    GeoIpService.GeoResult srcGeo = geoMap.get(srcIp);
    GeoIpService.GeoResult dstGeo = geoMap.get(dstIp);
    if (srcGeo == null && dstGeo == null) return "";

    String srcPart =
        srcGeo != null && srcGeo.countryCode() != null
            ? srcGeo.countryCode() + (srcGeo.org() != null ? "/" + srcGeo.org() : "")
            : "private";
    String dstPart =
        dstGeo != null && dstGeo.countryCode() != null
            ? dstGeo.countryCode() + (dstGeo.org() != null ? "/" + dstGeo.org() : "")
            : "private";
    return " [" + srcPart + " -> " + dstPart + "]";
  }

  private String buildTlsCertLabel(ConversationEntity conv) {
    List<String> parts = new ArrayList<>();
    if (conv.getTlsSubject() != null) parts.add("subject=" + conv.getTlsSubject());
    if (conv.getTlsIssuer() != null) parts.add("issuer=" + conv.getTlsIssuer());
    if (conv.getTlsNotAfter() != null) {
      boolean expired = conv.getTlsNotAfter().isBefore(LocalDateTime.now());
      String expiryPart = "expires=" + conv.getTlsNotAfter();
      if (expired) expiryPart += " EXPIRED";
      parts.add(expiryPart);
    }
    if (parts.isEmpty()) return "";
    return " [TLS: " + String.join(", ", parts) + "]";
  }

  private String buildUserPrompt(
      FileEntity file, AnalysisResultEntity analysis, String additionalContext) {

    int maxConversations =
        llmConfig.getStory() != null ? llmConfig.getStory().getMaxConversations() : 20;
    // Security alerts are capped at the same limit to keep the prompt within context-window budget.
    // The total count is still reported so the LLM knows the full scope.
    int maxAlerts = maxConversations;

    UUID fileId = file.getId();

    // Fetch only what we need — never load the full conversation table
    List<ConversationEntity> topConversations =
        conversationRepository.findTopByFileIdOrderByTotalBytesDesc(
            fileId, PageRequest.of(0, maxConversations));
    long totalConversations = conversationRepository.countByFileId(fileId);

    // Build geo map for all IPs appearing in the prompt (best-effort, empty on failure)
    Map<String, GeoIpService.GeoResult> geoMap;
    try {
      Set<String> promptIps = new HashSet<>();
      topConversations.forEach(
          c -> {
            promptIps.add(c.getSrcIp());
            promptIps.add(c.getDstIp());
          });
      geoMap = geoIpService.lookupExternal(promptIps);
    } catch (Exception e) {
      log.warn("Geo lookup failed during story generation: {}", e.getMessage());
      geoMap = Map.of();
    }

    List<Object[]> categoryRows = conversationRepository.findCategoryDistributionByFileId(fileId);

    long totalAtRisk = conversationRepository.countAtRiskByFileId(fileId);
    List<ConversationEntity> atRiskSample =
        totalAtRisk > 0
            ? conversationRepository.findAtRiskByFileIdLimited(fileId, maxAlerts)
            : Collections.emptyList();

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
    prompt.append(String.format("- End Time: %s\n", analysis.getEndTime()));
    prompt.append(String.format("- Total Conversations: %d\n\n", totalConversations));

    // Protocol breakdown
    if (analysis.getProtocolStats() != null && !analysis.getProtocolStats().isEmpty()) {
      prompt.append("## Protocol Breakdown\n");
      analysis
          .getProtocolStats()
          .forEach(
              (protocol, statsObj) -> {
                if (statsObj instanceof Map) {
                  @SuppressWarnings("unchecked")
                  Map<String, Object> stats = (Map<String, Object>) statsObj;
                  Object packets = stats.get("packetCount");
                  Object bytes = stats.get("bytes");
                  Object pct = stats.get("percentage");
                  prompt.append(
                      String.format(
                          "- %s: %s packets, %s bytes (%.1f%%)\n",
                          protocol,
                          packets,
                          bytes,
                          pct instanceof Number ? ((Number) pct).doubleValue() : 0.0));
                }
              });
      prompt.append("\n");
    }

    // Category distribution — aggregated at DB level, no entity loading
    if (!categoryRows.isEmpty()) {
      prompt.append("## Traffic Category Breakdown\n");
      for (Object[] row : categoryRows) {
        prompt.append(String.format("- %s: %s packets\n", row[0], row[1]));
      }
      prompt.append("\n");
    }

    // Top-N conversations by volume
    if (!topConversations.isEmpty()) {
      prompt.append(
          String.format(
              "## Top %d Conversations (by traffic volume, %d total)\n",
              topConversations.size(), totalConversations));
      for (int i = 0; i < topConversations.size(); i++) {
        ConversationEntity conv = topConversations.get(i);
        String appLabel =
            (conv.getAppName() != null && !conv.getAppName().isBlank())
                ? " [" + conv.getAppName() + "]"
                : "";
        String catLabel =
            (conv.getCategory() != null && !conv.getCategory().isBlank())
                ? " [CAT: " + conv.getCategory() + "]"
                : "";
        String riskLabel =
            (conv.getFlowRisks() != null && conv.getFlowRisks().length > 0)
                ? " [RISKS: " + String.join(", ", conv.getFlowRisks()) + "]"
                : "";
        String tlsCertLabel = buildTlsCertLabel(conv);
        String geoLabel = buildGeoLabel(conv.getSrcIp(), conv.getDstIp(), geoMap);
        prompt.append(
            String.format(
                "%d. %s:%s <-> %s:%s%s (%s%s%s%s%s, %d packets, %d bytes)\n",
                i + 1,
                conv.getSrcIp(),
                conv.getSrcPort() != null ? conv.getSrcPort() : "*",
                conv.getDstIp(),
                conv.getDstPort() != null ? conv.getDstPort() : "*",
                geoLabel,
                conv.getProtocol(),
                appLabel,
                catLabel,
                riskLabel,
                tlsCertLabel,
                conv.getPacketCount(),
                conv.getTotalBytes()));
      }
      if (totalConversations > maxConversations) {
        prompt.append(
            String.format(
                "... and %d more conversations not shown (increase STORY_MAX_CONVERSATIONS to include more).\n",
                totalConversations - maxConversations));
      }
      prompt.append("\n");
    }

    // Security alerts — capped to avoid blowing the context window
    if (totalAtRisk > 0) {
      prompt.append(
          String.format(
              "## Security Alerts (%d total conversations with nDPI risk flags; showing top %d)\n",
              totalAtRisk, atRiskSample.size()));
      for (ConversationEntity conv : atRiskSample) {
        String appLabel =
            (conv.getAppName() != null && !conv.getAppName().isBlank())
                ? " [" + conv.getAppName() + "]"
                : "";
        String geoLabel = buildGeoLabel(conv.getSrcIp(), conv.getDstIp(), geoMap);
        prompt.append(
            String.format(
                "- %s:%s <-> %s:%s%s (%s%s): %s\n",
                conv.getSrcIp(),
                conv.getSrcPort() != null ? conv.getSrcPort() : "*",
                conv.getDstIp(),
                conv.getDstPort() != null ? conv.getDstPort() : "*",
                geoLabel,
                conv.getProtocol(),
                appLabel,
                String.join(", ", conv.getFlowRisks())));
      }
      if (totalAtRisk > maxAlerts) {
        prompt.append(
            String.format(
                "... and %d more at-risk conversations not shown.\n", totalAtRisk - maxAlerts));
      }
      prompt.append("\n");
    }

    prompt.append("## Analysis Limitations\n");
    prompt.append(
        "The following data was NOT available during this analysis — do not infer or hallucinate details about them:\n");
    prompt.append("- Packet payloads or raw bytes (not captured)\n");
    prompt.append("- Application-layer content (HTTP bodies, DNS query names, etc.)\n");
    prompt.append("- Any conversations beyond those listed above\n\n");

    if (additionalContext != null && !additionalContext.isBlank()) {
      prompt.append("## Additional Context from Analyst\n");
      prompt.append(additionalContext.strip()).append("\n\n");
    }

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

      // Parse suggested questions (optional)
      List<String> suggestedQuestions = parseSuggestedQuestions(data.get("suggestedQuestions"));

      log.info(
          "Successfully parsed story: {} narrative sections, {} highlights, {} timeline events, {} suggested questions",
          narrative.size(),
          highlights.size(),
          timeline.size(),
          suggestedQuestions.size());

      return StoryResponse.builder()
          .id(storyId.toString())
          .fileId(fileId.toString())
          .generatedAt(System.currentTimeMillis())
          .narrative(narrative)
          .highlights(highlights)
          .timeline(timeline)
          .suggestedQuestions(suggestedQuestions)
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

  /** Parse suggested questions from JSON */
  @SuppressWarnings("unchecked")
  private List<String> parseSuggestedQuestions(Object data) {
    if (data == null) return new ArrayList<>();
    try {
      return ((List<Object>) data)
          .stream()
              .filter(q -> q instanceof String)
              .map(q -> (String) q)
              .filter(q -> !q.isBlank())
              .limit(3)
              .collect(Collectors.toList());
    } catch (Exception e) {
      log.warn("Failed to parse suggestedQuestions: {}", e.getMessage());
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
