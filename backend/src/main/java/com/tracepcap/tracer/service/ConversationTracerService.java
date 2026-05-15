package com.tracepcap.tracer.service;

import com.tracepcap.analysis.entity.ConversationEntity;
import com.tracepcap.analysis.entity.PacketEntity;
import com.tracepcap.analysis.repository.ConversationRepository;
import com.tracepcap.analysis.repository.PacketRepository;
import com.tracepcap.common.exception.LlmException;
import com.tracepcap.story.service.LlmClient;
import com.tracepcap.tracer.dto.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class ConversationTracerService {

  private final ConversationRepository conversationRepository;
  private final PacketRepository packetRepository;
  private final LlmClient llmClient;

  /** LRU cache (max 500 entries) to avoid repeating LLM calls for the same conversation. */
  private final Map<UUID, List<StepExplanation>> explanationCache =
      Collections.synchronizedMap(new LinkedHashMap<>(128, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<UUID, List<StepExplanation>> eldest) {
          return size() > 500;
        }
      });

  private static final DateTimeFormatter TS_FMT =
      DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");

  // ── Public API ────────────────────────────────────────────────────────────

  public TracerStepsResponse getSteps(UUID conversationId) {
    ConversationEntity conv = conversationRepository.findById(conversationId)
        .orElseThrow(() -> new NoSuchElementException("Conversation not found: " + conversationId));

    List<PacketEntity> packets =
        packetRepository.findByConversationIdOrderByPacketNumberAsc(conversationId);

    List<TracerStep> steps = new ArrayList<>();
    for (int i = 0; i < packets.size(); i++) {
      PacketEntity p = packets.get(i);
      String direction = p.getSrcIp().equals(conv.getSrcIp()) ? "CLIENT" : "SERVER";
      steps.add(TracerStep.builder()
          .stepIndex(i)
          .packetNumber(p.getPacketNumber())
          .timestamp(p.getTimestamp() != null ? p.getTimestamp().format(TS_FMT) : null)
          .direction(direction)
          .protocol(p.getProtocol())
          .size(p.getPacketSize())
          .info(p.getInfo())
          .payloadHex(p.getPayload())
          .build());
    }

    return TracerStepsResponse.builder()
        .conversationId(conversationId.toString())
        .srcIp(conv.getSrcIp())
        .srcPort(conv.getSrcPort())
        .dstIp(conv.getDstIp())
        .dstPort(conv.getDstPort())
        .protocol(conv.getProtocol())
        .appName(conv.getAppName())
        .steps(steps)
        .build();
  }

  public TracerExplainResponse explainSteps(UUID conversationId) {
    // Return from cache if available
    List<StepExplanation> cached = explanationCache.get(conversationId);
    if (cached != null) {
      log.info("Returning cached explanations for conversation {}", conversationId);
      return TracerExplainResponse.builder()
          .conversationId(conversationId.toString())
          .explanations(cached)
          .build();
    }

    ConversationEntity conv = conversationRepository.findById(conversationId)
        .orElseThrow(() -> new NoSuchElementException("Conversation not found: " + conversationId));

    List<PacketEntity> packets =
        packetRepository.findByConversationIdOrderByPacketNumberAsc(conversationId);

    if (packets.isEmpty()) {
      return TracerExplainResponse.builder()
          .conversationId(conversationId.toString())
          .explanations(Collections.emptyList())
          .build();
    }

    String systemPrompt = buildSystemPrompt(conv);
    String userPrompt = buildUserPrompt(conv, packets);

    log.info("Generating tracer explanations for conversation {} ({} packets)", conversationId, packets.size());
    String llmResponse;
    try {
      llmResponse = llmClient.generateCompletion(systemPrompt, userPrompt);
    } catch (LlmException e) {
      log.warn("LLM call failed for tracer {}: {}", conversationId, e.getMessage());
      String errorMsg = e.getErrorCode() == com.tracepcap.common.exception.LlmException.ErrorCode.LLM_TIMEOUT
          ? "AI explanation unavailable — the language model took too long to respond."
          : "AI explanation unavailable — could not reach the language model. Check your LLM configuration.";
      return TracerExplainResponse.builder()
          .conversationId(conversationId.toString())
          .explanations(Collections.emptyList())
          .error(errorMsg)
          .build();
    }

    List<StepExplanation> explanations = parseExplanations(llmResponse, packets.size());
    explanationCache.put(conversationId, explanations);

    return TracerExplainResponse.builder()
        .conversationId(conversationId.toString())
        .explanations(explanations)
        .build();
  }

  // ── Prompt building ───────────────────────────────────────────────────────

  private String buildSystemPrompt(ConversationEntity conv) {
    return """
        You are a network protocol expert analysing a packet capture (PCAP) file.
        For each packet in the conversation below, provide a concise 1-2 sentence plain-English explanation of what is happening at that network step.
        Focus on what the packet means in context: handshakes, data transfers, acknowledgements, protocol-specific meaning.
        Format your response as a numbered list with one entry per packet, using the format:
        STEP <n>: <explanation>
        Keep each explanation to 1-2 sentences. Use plain language suitable for a security analyst.
        Conversation: %s:%s -> %s:%s (%s%s)""".formatted(
        conv.getSrcIp(),
        conv.getSrcPort() != null ? conv.getSrcPort() : "?",
        conv.getDstIp(),
        conv.getDstPort() != null ? conv.getDstPort() : "?",
        conv.getProtocol(),
        conv.getAppName() != null ? " / " + conv.getAppName() : "");
  }

  private String buildUserPrompt(ConversationEntity conv, List<PacketEntity> packets) {
    StringBuilder sb = new StringBuilder();
    sb.append("Explain each of the following ").append(packets.size())
        .append(" packets in the conversation.\n\n");

    for (int i = 0; i < packets.size(); i++) {
      PacketEntity p = packets.get(i);
      String dir = p.getSrcIp().equals(conv.getSrcIp()) ? "CLIENT->SERVER" : "SERVER->CLIENT";
      sb.append("Packet ").append(i + 1).append(":\n");
      sb.append("  Direction: ").append(dir).append("\n");
      sb.append("  Protocol: ").append(p.getProtocol()).append("\n");
      sb.append("  Size: ").append(p.getPacketSize()).append(" bytes\n");
      if (p.getInfo() != null && !p.getInfo().isBlank()) {
        sb.append("  Info: ").append(p.getInfo()).append("\n");
      }
      String ascii = extractAsciiPayload(p.getPayload());
      if (!ascii.isEmpty()) {
        sb.append("  Payload (ASCII): ").append(ascii).append("\n");
      }
      sb.append("\n");
    }
    return sb.toString();
  }

  /**
   * Converts up to the first 64 bytes of a hex payload string to a printable ASCII excerpt.
   * Non-printable bytes are replaced with '.'. Returns empty string if payload is null/blank.
   */
  private String extractAsciiPayload(String hexPayload) {
    if (hexPayload == null || hexPayload.isBlank()) return "";
    // Strip any whitespace
    String hex = hexPayload.replaceAll("\\s", "");
    int byteLen = Math.min(hex.length() / 2, 64);
    if (byteLen == 0) return "";
    StringBuilder ascii = new StringBuilder(byteLen);
    for (int i = 0; i < byteLen; i++) {
      int b = Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
      ascii.append((b >= 0x20 && b < 0x7f) ? (char) b : '.');
    }
    // Only return if there's meaningful printable content (at least 4 consecutive printable chars)
    String result = ascii.toString();
    if (!result.matches(".*[\\x20-\\x7e]{4,}.*")) return "";
    return result;
  }

  private List<StepExplanation> parseExplanations(String llmResponse, int packetCount) {
    // Parse "STEP N: explanation" lines from the LLM response
    List<StepExplanation> result = new ArrayList<>();
    String[] lines = llmResponse.split("\n");
    Map<Integer, StringBuilder> stepMap = new LinkedHashMap<>();

    Integer currentStep = null;
    for (String line : lines) {
      String trimmed = line.trim();
      if (trimmed.isEmpty()) continue;

      // Match "STEP N:" or "N." or "Packet N:"
      java.util.regex.Matcher m = java.util.regex.Pattern
          .compile("^(?:STEP\\s+|Packet\\s+)?(\\d+)[.:]\\s*(.*)")
          .matcher(trimmed);
      if (m.matches()) {
        int n = Integer.parseInt(m.group(1)) - 1; // 0-indexed
        if (n >= 0 && n < packetCount) {
          currentStep = n;
          stepMap.computeIfAbsent(n, k -> new StringBuilder()).append(m.group(2));
        }
      } else if (currentStep != null) {
        // Continuation line
        stepMap.computeIfAbsent(currentStep, k -> new StringBuilder())
            .append(" ").append(trimmed);
      }
    }

    // Build result list; fill gaps with a generic message
    for (int i = 0; i < packetCount; i++) {
      StringBuilder sb = stepMap.get(i);
      result.add(StepExplanation.builder()
          .stepIndex(i)
          .explanation(sb != null ? sb.toString().trim() : "Packet in the network conversation.")
          .build());
    }
    return result;
  }
}
