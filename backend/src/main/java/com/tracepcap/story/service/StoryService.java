package com.tracepcap.story.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracepcap.analysis.dto.TimelineDataDto;
import com.tracepcap.analysis.entity.AnalysisResultEntity;
import com.tracepcap.analysis.repository.AnalysisResultRepository;
import com.tracepcap.analysis.repository.ConversationRepository;
import com.tracepcap.analysis.service.TimelineService;
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
  private final StoryAggregatesService storyAggregatesService;
  private final FindingsService findingsService;
  private final InvestigationService investigationService;
  private final TimelineService timelineService;

  /**
   * Generate a story for a PCAP file using LLM
   *
   * @param fileId the file ID
   * @return generated story response
   */
  public StoryResponse generateStory(UUID fileId, String additionalContext) {
    return generateStory(fileId, additionalContext, null, null, null);
  }

  public StoryResponse generateStory(UUID fileId, String additionalContext, String customPrompt) {
    return generateStory(fileId, additionalContext, customPrompt, null, null);
  }

  // Not annotated @Transactional: LLM calls can take several minutes and holding an open DB
  // connection for that duration risks connection pool exhaustion. The delete and save operations
  // inside are each transactional by default (Spring's per-operation default).
  public StoryResponse generateStory(UUID fileId, String additionalContext, String customPrompt,
      Integer maxFindings, Integer maxRiskMatrix) {
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
      // If the user supplied a pre-edited custom prompt (retry after context-length error),
      // skip all prompt-building phases and send it directly to the LLM.
      if (customPrompt != null && !customPrompt.isBlank()) {
        log.info("Using user-supplied custom prompt for file: {}", fileId);
        StoryAggregates aggregates = storyAggregatesService.compute(
            fileId, List.of(), conversationRepository.countByFileId(fileId));
        List<Finding> findings = findingsService.detectAll(
            fileId, conversationRepository.countByFileId(fileId), analysis.getTotalBytes());
        String storyContent = llmClient.generateCompletion(buildSystemPrompt(), customPrompt);
        StoryResponse storyResponse = parseStoryContent(storyContent, storyId, fileId);
        storyResponse.setAggregates(aggregates);
        storyResponse.setFindings(findings);
        StoryEntity story = StoryEntity.builder()
            .id(storyId).fileId(fileId).generatedAt(generatedAt)
            .status(StoryEntity.StoryStatus.COMPLETED)
            .modelUsed(llmConfig.getApi().getModel())
            .content(objectMapper.writeValueAsString(storyResponse))
            .build();
        storyRepository.save(story);
        log.info("Successfully generated story from custom prompt for file: {}", fileId);
        return storyResponse;
      }

      long totalConversations = conversationRepository.countByFileId(fileId);

      // Run all deterministic detectors
      List<Finding> findings =
          findingsService.detectAll(fileId, totalConversations, analysis.getTotalBytes());
      log.info("Detected {} findings for file: {}", findings.size(), fileId);

      // Pre-compute aggregates over the full dataset for the aggregates panel and prompt context
      StoryAggregates aggregates =
          storyAggregatesService.compute(fileId, List.of(), totalConversations);
      log.info(
          "Computed aggregates for file: {} ({} beacon candidates, {} ASN entries)",
          fileId,
          aggregates.getBeaconCandidates().size(),
          aggregates.getTopExternalAsns().size());

      // Fetch timeline bins for LLM context (max 50 bins)
      List<TimelineDataDto> timelineBins = List.of();
      try {
        timelineBins = timelineService.getTimelineData(fileId, 1, 50);
      } catch (Exception e) {
        log.warn("Failed to fetch timeline bins for story: {}", e.getMessage());
      }

      // Phase 1: LLM generates hypotheses + queries
      List<InvestigationStep> investigationSteps = List.of();
      try {
        String phase1Json = llmClient.generateCompletion(
            buildHypothesisSystemPrompt(),
            buildHypothesisUserPrompt(file, analysis, additionalContext, aggregates, findings, timelineBins, maxFindings, maxRiskMatrix)
        );
        var phase1 = parseHypothesesAndQueries(phase1Json);
        investigationSteps =
            investigationService.executeQueries(fileId, phase1.queries(), phase1.hypotheses());
        log.info(
            "Investigation complete: {} steps for file: {}", investigationSteps.size(), fileId);
      } catch (Exception e) {
        log.warn(
            "Investigation phase failed, falling back to direct narrative: {}", e.getMessage());
      }

      // Phase 2: LLM writes narrative with investigation results
      String storyContent = llmClient.generateCompletion(
          buildSystemPrompt(),
          buildNarrativeUserPrompt(file, analysis, additionalContext, aggregates, findings, timelineBins, investigationSteps, maxFindings, maxRiskMatrix)
      );

      // Parse LLM response and attach aggregates + findings
      StoryResponse storyResponse = parseStoryContent(storyContent, storyId, fileId);
      storyResponse.setAggregates(aggregates);
      storyResponse.setFindings(findings);
      storyResponse.setInvestigationSteps(investigationSteps.isEmpty() ? null : investigationSteps);

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

  /** Build system prompt for LLM */
  private String buildSystemPrompt() {
    return """
            You are a cybersecurity analyst. Your ONLY job is to write a clear, technical narrative from the pre-computed deterministic findings provided. Do NOT re-interpret the raw data. Do NOT invent findings not listed. Do NOT contradict any metric given.

            You must respond ONLY with valid JSON:
            {
              "narrative": [
                { "title": "...", "content": "...", "type": "summary|detail|anomaly|conclusion",
                  "relatedData": { "packets": [], "conversations": [], "hosts": [] } }
              ],
              "highlights": [
                { "id": "h1", "type": "anomaly|warning|insight|info", "title": "...", "description": "...", "timestamp": null }
              ],
              "timeline": [
                { "timestamp": null, "title": "...", "description": "...", "type": "normal|suspicious|critical",
                  "relatedData": { "packets": [], "conversations": [] } }
              ],
              "suggestedQuestions": ["...", "...", "..."]
            }

            Rules:
            - Every CRITICAL or HIGH severity finding MUST appear in at least one highlight and one timeline event.
            - anomaly highlight type for CRITICAL findings; warning for HIGH; insight for MEDIUM/LOW.
            - Timeline event type: critical for CRITICAL findings; suspicious for HIGH; normal for MEDIUM/LOW.
            - suggestedQuestions: exactly 3, specific to the actual findings, not generic.
            - Narrative: "summary" section first covering overall picture, then "detail" sections per major finding cluster, "conclusion" last with recommendations.
            - Write for a technical security analyst. Reference specific IPs, ports, counts, and ratios from the findings.
            - The aggregates section provides full-dataset context — use it to frame the scale of findings.
            """;
  }

  /**
   * Build the base prompt context with findings and aggregates. Callers append their own closing
   * instruction.
   */
  private static final int DEFAULT_MAX_FINDINGS = 20;
  private static final int DEFAULT_MAX_RISK_MATRIX = 15;

  private String buildBasePromptContext(
      FileEntity file, AnalysisResultEntity analysis, String additionalContext,
      StoryAggregates agg, List<Finding> findings,
      Integer maxFindingsOverride, Integer maxRiskMatrixOverride) {

    UUID fileId = file.getId();
    List<Object[]> categoryRows = conversationRepository.findCategoryDistributionByFileId(fileId);

    StringBuilder prompt = new StringBuilder();
    prompt.append(
        "Analyze this network traffic capture and write a narrative from the findings below:\n\n");

    prompt.append("## File Information\n");
    prompt.append(String.format("- Filename: %s\n", file.getFileName()));
    prompt.append(String.format("- File Size: %d bytes\n", file.getFileSize()));
    prompt.append("\n");

    prompt.append("## Traffic Summary\n");
    prompt.append(String.format("- Total Packets: %d\n", analysis.getPacketCount()));
    prompt.append(String.format("- Total Bytes: %d\n", analysis.getTotalBytes()));
    prompt.append(String.format("- Duration: %d ms\n", analysis.getDurationMs()));
    prompt.append(String.format("- Start Time: %s\n", analysis.getStartTime()));
    prompt.append(String.format("- End Time: %s\n", analysis.getEndTime()));
    long totalConversations =
        agg.getCoverage() != null ? agg.getCoverage().getTotalConversations() : 0;
    prompt.append(String.format("- Total Conversations: %d\n\n", totalConversations));

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

    if (!categoryRows.isEmpty()) {
      prompt.append("## Traffic Category Breakdown\n");
      for (Object[] row : categoryRows) {
        prompt.append(String.format("- %s: %s packets\n", row[0], row[1]));
      }
      prompt.append("\n");
    }

    // ── Deterministic Findings ──────────────────────────────────────────────
    int maxF = maxFindingsOverride != null && maxFindingsOverride > 0
        ? maxFindingsOverride : DEFAULT_MAX_FINDINGS;
    List<Finding> cappedFindings = findings.size() > maxF ? findings.subList(0, maxF) : findings;
    prompt.append(String.format(
        "## Deterministic Findings — %d findings shown (of %d total), ordered by severity\n",
        cappedFindings.size(), findings.size()));
    prompt.append("(These are computed from the full dataset. Treat them as ground truth.)\n");
    for (Finding f : cappedFindings) {
      prompt.append(String.format("\n### [%s] %s — %s\n", f.getSeverity(), f.getType(), f.getTitle()));
      prompt.append(f.getSummary()).append("\n");
      if (f.getMetrics() != null && !f.getMetrics().isEmpty()) {
        prompt.append("Metrics: ");
        prompt.append(
            f.getMetrics().entrySet().stream()
                .map(e -> e.getKey() + ": " + e.getValue())
                .collect(Collectors.joining(", ")));
        prompt.append("\n");
      }
      if (f.getAffectedIps() != null && !f.getAffectedIps().isEmpty()) {
        prompt.append("Affected IPs: ").append(String.join(", ", f.getAffectedIps())).append("\n");
      } else {
        prompt.append("Affected IPs: N/A\n");
      }
    }
    prompt.append("\n");

    // ── Full-Dataset Traffic Aggregates ────────────────────────────────────
    prompt.append("## Full-Dataset Traffic Aggregates\n");
    prompt.append(String.format("- Unknown application traffic: %.1f%%\n", agg.getUnknownAppPct()));

    if (agg.getTopExternalAsns() != null && !agg.getTopExternalAsns().isEmpty()) {
      prompt.append("### Top External Destinations\n");
      for (int i = 0; i < agg.getTopExternalAsns().size(); i++) {
        StoryAggregates.AsnEntry e = agg.getTopExternalAsns().get(i);
        String label = e.getOrg() != null ? e.getOrg() : "Unknown";
        if (e.getAsn() != null) label = e.getAsn() + " " + label;
        if (e.getCountry() != null) label += " (" + e.getCountry() + ")";
        prompt.append(
            String.format(
                "%d. %s — %d flows, %.1f%% of bytes\n",
                i + 1, label, e.getFlowCount(), e.getPct()));
      }
    }

    if (agg.getProtocolRiskMatrix() != null && !agg.getProtocolRiskMatrix().isEmpty()) {
      prompt.append("### Protocol Risk Matrix\n");
      int maxR = maxRiskMatrixOverride != null && maxRiskMatrixOverride > 0
          ? maxRiskMatrixOverride : DEFAULT_MAX_RISK_MATRIX;
      List<StoryAggregates.ProtocolRiskEntry> riskMatrix = agg.getProtocolRiskMatrix().size() > maxR
          ? agg.getProtocolRiskMatrix().subList(0, maxR) : agg.getProtocolRiskMatrix();
      for (StoryAggregates.ProtocolRiskEntry e : riskMatrix) {
        double riskPct = e.getTotal() > 0 ? e.getAtRisk() * 100.0 / e.getTotal() : 0;
        prompt.append(
            String.format(
                "- %s: %d total, %d at-risk (%.1f%%)\n",
                e.getProtocol(), e.getTotal(), e.getAtRisk(), riskPct));
      }
    }

    StoryAggregates.TlsAnomalySummary tls = agg.getTlsAnomalySummary();
    if (tls != null && tls.getTotal() > 0) {
      prompt.append("### TLS Anomaly Summary\n");
      prompt.append(
          String.format(
              "- Self-signed: %d, Expired: %d, Unknown CA: %d (of %d total TLS flows)\n",
              tls.getSelfSigned(), tls.getExpired(), tls.getUnknownCa(), tls.getTotal()));
    }

    if (agg.getBeaconCandidates() != null && !agg.getBeaconCandidates().isEmpty()) {
      prompt.append("### Beacon Candidates\n");
      for (StoryAggregates.BeaconCandidate b : agg.getBeaconCandidates()) {
        String app = b.getAppName() != null ? " [" + b.getAppName() + "]" : "";
        long intervalSec = b.getAvgIntervalMs() / 1000;
        String interval =
            intervalSec < 60
                ? intervalSec + "s"
                : (intervalSec / 60) + "m " + (intervalSec % 60) + "s";
        prompt.append(
            String.format(
                "- %s -> %s:%s (%s%s) — %d flows, avg interval %s, jitter %.0f%%\n",
                b.getSrcIp(),
                b.getDstIp() != null ? b.getDstIp() : "?",
                b.getDstPort() != null ? b.getDstPort() : "*",
                b.getProtocol(),
                app,
                b.getFlowCount(),
                interval,
                b.getCv() * 100));
      }
    }
    prompt.append("\n");

    prompt.append("## Analysis Limitations\n");
    prompt.append("- Packet payloads and HTTP bodies not available\n");
    prompt.append("- DNS query names and TLS SNI not captured\n");
    prompt.append("- Benign (non-risk) conversations not individually listed\n\n");

    if (additionalContext != null && !additionalContext.isBlank()) {
      prompt.append("## Additional Context from Analyst\n");
      prompt.append(additionalContext.strip()).append("\n\n");
    }

    return prompt.toString();
  }

  /** Build hypothesis system prompt for Phase 1 */
  private String buildHypothesisSystemPrompt() {
    return """
        You are a cybersecurity analyst. Your ONLY job is to form hypotheses and specify targeted database queries to test them, based on the pre-computed findings and traffic timeline provided.

        You must respond ONLY with valid JSON in this exact format:
        {
          "hypotheses": [
            {
              "id": "h1",
              "queryRef": "q1",
              "hypothesis": "Concise 1-sentence testable hypothesis referencing specific IPs or ports",
              "confidence": "HIGH"
            }
          ],
          "queries": [
            {
              "id": "q1",
              "label": "Short description of what you are looking for",
              "srcIp": null,
              "dstIp": null,
              "dstPort": null,
              "protocol": null,
              "appName": null,
              "category": null,
              "hasRisks": null,
              "hasTlsAnomaly": null,
              "riskType": null,
              "minBytes": null,
              "maxBytes": null,
              "minFlows": null
            }
          ]
        }

        Rules:
        - Generate 1 to 5 queries. No more.
        - Each query MUST set at least 1 non-null filter field. Do NOT generate catch-all queries with all nulls.
        - Each hypothesis must reference exactly one query via queryRef.
        - Only use IPs, ports, and protocols you have seen in the findings or aggregates.
        - Do NOT guess or invent values not present in the provided data.
        - confidence must be one of: HIGH, MEDIUM, LOW.
        - Use the traffic timeline to anchor hypotheses to specific time windows when possible.
        - Available filter fields: srcIp, dstIp, dstPort, protocol, appName, category, hasRisks (boolean), hasTlsAnomaly (boolean), riskType (string), minBytes (number), maxBytes (number), minFlows (number).
        - minBytes and maxBytes are PER-CONVERSATION byte counts, NOT aggregate totals. Do NOT set minBytes to an aggregate total from the findings (e.g. total bytes for an IP). Only use minBytes if you want conversations larger than a specific individual flow size.
        - To find unknown/unidentified application traffic, set hasRisks=null and appName=null (leave appName as null — do not set it to "UNKNOWN_APP" or any string).
        - To find traffic from a specific IP, use srcIp only — do not combine srcIp with minBytes.
        - riskType values must match exactly what appears in the findings, e.g. "susp_entropy", "unidirectional_traffic".
        """;
  }

  /** Build hypothesis user prompt for Phase 1 */
  private String buildHypothesisUserPrompt(
      FileEntity file, AnalysisResultEntity analysis, String additionalContext,
      StoryAggregates aggregates, List<Finding> findings, List<TimelineDataDto> timelineBins,
      Integer maxFindings, Integer maxRiskMatrix) {

    StringBuilder prompt = new StringBuilder(
        buildBasePromptContext(file, analysis, additionalContext, aggregates, findings, maxFindings, maxRiskMatrix));

    appendTimelineBins(prompt, timelineBins);

    prompt.append(
        "Based on the findings, aggregates, and timeline above, generate hypotheses and specify database queries to investigate the most suspicious activity.\n");
    prompt.append("Respond ONLY with valid JSON.");

    return prompt.toString();
  }

  /** Build the full narrative user prompt for Phase 2 */
  private String buildNarrativeUserPrompt(
      FileEntity file, AnalysisResultEntity analysis, String additionalContext,
      StoryAggregates aggregates, List<Finding> findings,
      List<TimelineDataDto> timelineBins, List<InvestigationStep> investigationSteps,
      Integer maxFindings, Integer maxRiskMatrix) {

    StringBuilder prompt = new StringBuilder(
        buildBasePromptContext(file, analysis, additionalContext, aggregates, findings, maxFindings, maxRiskMatrix));

    appendTimelineBins(prompt, timelineBins);

    if (!investigationSteps.isEmpty()) {
      prompt.append("## Investigation Results\n");
      prompt.append(
          "The following targeted queries were executed against the full dataset to gather evidence for each hypothesis.\n\n");
      for (InvestigationStep step : investigationSteps) {
        InvestigationQuery q = step.getQuery();
        prompt.append(String.format("### Query %s: \"%s\"\n", q.getId(), q.getLabel()));
        if (step.getHypothesis() != null) {
          prompt.append(
              String.format(
                  "Hypothesis [%s]: %s\n",
                  step.getHypothesis().getConfidence(), step.getHypothesis().getHypothesis()));
        }
        prompt.append(
            String.format(
                "Total matching conversations: %d (showing top %d)\n",
                step.getConversationCount(), step.getConversations().size()));
        if (!step.getConversations().isEmpty()) {
          prompt.append("| src | dst | port | proto | app | bytes | start | risks |\n");
          prompt.append("|-----|-----|------|-------|-----|-------|-------|-------|\n");
          for (ConversationEvidence ev : step.getConversations()) {
            String risks = ev.getFlowRisks() != null ? String.join(",", ev.getFlowRisks()) : "";
            String app = ev.getAppName() != null ? ev.getAppName() : "-";
            String start = ev.getStartTime() != null ? ev.getStartTime().substring(11, 19) : "-";
            prompt.append(
                String.format(
                    "| %s | %s | %d | %s | %s | %d | %s | %s |\n",
                    ev.getSrcIp(),
                    ev.getDstIp(),
                    ev.getDstPort() != null ? ev.getDstPort() : 0,
                    ev.getProtocol(),
                    app,
                    ev.getTotalBytes() != null ? ev.getTotalBytes() : 0,
                    start,
                    risks));
          }
        } else {
          prompt.append("No matching conversations found.\n");
        }
        prompt.append("\n");
      }
    }

    prompt.append(
        "Write the final narrative story using all evidence above. Confirm or refute each hypothesis using the investigation results. Respond ONLY with valid JSON.");

    return prompt.toString();
  }

  /** Append timeline bins section to a prompt builder */
  private void appendTimelineBins(StringBuilder prompt, List<TimelineDataDto> bins) {
    if (bins == null || bins.isEmpty()) return;
    prompt.append("## Traffic Timeline (up to 50 time windows)\n");
    prompt.append("| time | packets | bytes | notes |\n");
    prompt.append("|------|---------|-------|-------|\n");
    for (TimelineDataDto bin : bins) {
      String ts = bin.getTimestamp() != null ? bin.getTimestamp().toString().substring(0, 19) : "-";
      long bytes = bin.getBytes() != null ? bin.getBytes() : 0;
      String bytesHuman =
          bytes > 1_048_576
              ? String.format("%.1fMB", bytes / 1_048_576.0)
              : bytes > 1024 ? String.format("%.1fKB", bytes / 1024.0) : bytes + "B";
      prompt.append(
          String.format(
              "| %s | %d | %s |\n",
              ts, bin.getPacketCount() != null ? bin.getPacketCount() : 0, bytesHuman));
    }
    prompt.append("\n");
  }

  private record ParsedPhase1(List<InvestigationQuery> queries, List<Hypothesis> hypotheses) {}

  /** Parse Phase 1 LLM response into hypotheses and queries */
  private ParsedPhase1 parseHypothesesAndQueries(String content) {
    try {
      String json = extractJson(content);
      Map<String, Object> data = objectMapper.readValue(json, new TypeReference<>() {});

      List<InvestigationQuery> queries = new ArrayList<>();
      List<Hypothesis> hypotheses = new ArrayList<>();

      Object queriesRaw = data.get("queries");
      if (queriesRaw instanceof List<?> qList) {
        for (Object item : qList) {
          try {
            String itemJson = objectMapper.writeValueAsString(item);
            queries.add(objectMapper.readValue(itemJson, InvestigationQuery.class));
          } catch (Exception e) {
            log.warn("Skipping malformed query: {}", e.getMessage());
          }
        }
      }

      Object hypothesesRaw = data.get("hypotheses");
      if (hypothesesRaw instanceof List<?> hList) {
        for (Object item : hList) {
          try {
            String itemJson = objectMapper.writeValueAsString(item);
            hypotheses.add(objectMapper.readValue(itemJson, Hypothesis.class));
          } catch (Exception e) {
            log.warn("Skipping malformed hypothesis: {}", e.getMessage());
          }
        }
      }

      log.info("Parsed phase 1: {} queries, {} hypotheses", queries.size(), hypotheses.size());
      return new ParsedPhase1(queries, hypotheses);
    } catch (Exception e) {
      log.error("Failed to parse phase 1 LLM response: {}", e.getMessage());
      return new ParsedPhase1(List.of(), List.of());
    }
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
