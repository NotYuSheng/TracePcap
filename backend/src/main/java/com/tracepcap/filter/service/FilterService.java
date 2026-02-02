package com.tracepcap.filter.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.service.FileService;
import com.tracepcap.file.service.StorageService;
import com.tracepcap.filter.dto.*;
import com.tracepcap.story.service.LlmClient;
import java.io.File;
import java.nio.file.Files;
import java.util.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.springframework.stereotype.Service;

/** Service for filter generation and execution */
@Slf4j
@Service
@RequiredArgsConstructor
public class FilterService {

  private final LlmClient llmClient;
  private final FileService fileService;
  private final StorageService storageService;
  private final ObjectMapper objectMapper;

  private static final int MAX_PACKETS = 100; // Limit results for performance
  private static final int MAX_GENERATION_RETRIES = 3; // Maximum retries for filter generation

  /**
   * Validate BPF filter syntax using pcap4j
   *
   * @param bpfFilter The filter to validate
   * @param pcapFile A PCAP file to use for validation
   * @return Validation result with error message if invalid
   */
  private ValidationResult validateBpfFilter(String bpfFilter, File pcapFile) {
    if (bpfFilter == null || bpfFilter.trim().isEmpty()) {
      return new ValidationResult(false, "Filter cannot be empty");
    }

    try (PcapHandle handle = Pcaps.openOffline(pcapFile.getAbsolutePath())) {
      try {
        handle.setFilter(bpfFilter.trim(), BpfProgram.BpfCompileMode.OPTIMIZE);
        log.debug("BPF filter validation successful: {}", bpfFilter);
        return new ValidationResult(true, null);
      } catch (Exception e) {
        String errorMsg = e.getMessage();
        log.warn("BPF filter validation failed for '{}': {}", bpfFilter, errorMsg);
        return new ValidationResult(false, "Invalid BPF syntax: " + errorMsg);
      }
    } catch (Exception e) {
      log.error("Error opening PCAP file for validation", e);
      return new ValidationResult(false, "Unable to validate filter: " + e.getMessage());
    }
  }

  /** Generate a pcap filter from natural language query using LLM with validation and retry */
  public FilterGenerationResponse generateFilter(UUID fileId, String naturalLanguageQuery) {
    log.info("Generating filter for file {} with query: {}", fileId, naturalLanguageQuery);

    // Verify file exists and get PCAP file for validation
    FileEntity fileEntity = fileService.getFileById(fileId);
    File pcapFile = null;

    try {
      // Download PCAP file to temporary location for validation
      pcapFile = Files.createTempFile("pcap-validation-", ".pcap").toFile();
      storageService.downloadFileToLocal(fileEntity.getMinioPath(), pcapFile);

      String systemPrompt =
          """
                    You are an expert network security analyst specialized in creating pcap filters.
                    Your task is to convert natural language queries into valid BPF (Berkeley Packet Filter) syntax.

                    BPF Filter Syntax Reference:
                    - Protocols: tcp, udp, icmp, ip, arp, ip6
                    - Directions: src, dst
                    - Addresses: host 192.168.1.1, net 192.168.1.0/24
                    - Ports: port 80, portrange 20-80
                    - Logical operators: and, or, not
                    - Comparisons: greater, less

                    Common Examples:
                    - HTTP traffic: "tcp port 80 or tcp port 443"
                    - DNS queries: "udp port 53"
                    - Traffic from specific IP: "src host 192.168.1.1"
                    - SSH connections: "tcp port 22"
                    - All traffic to/from IP: "host 192.168.1.1"
                    - Large packets: "greater 1000"

                    Respond ONLY with valid JSON in this exact format (no markdown, no extra text):
                    {
                      "filter": "the BPF filter string",
                      "explanation": "clear explanation of what this filter does",
                      "confidence": 0.95,
                      "suggestions": ["optional suggestion 1", "optional suggestion 2"]
                    }

                    The confidence should be between 0.0 and 1.0 based on how certain you are about the filter.
                    Include suggestions only if there are alternative approaches or refinements.
                    """;

      String userPrompt = String.format("Create a BPF filter for: %s", naturalLanguageQuery);
      FilterGenerationResponse response = null;
      String lastValidationError = null;

      // Retry loop for filter generation with validation
      for (int attempt = 1; attempt <= MAX_GENERATION_RETRIES; attempt++) {
        log.info("Filter generation attempt {}/{}", attempt, MAX_GENERATION_RETRIES);

        try {
          String llmResponse = llmClient.generateCompletion(systemPrompt, userPrompt);
          log.debug("LLM Response (attempt {}): {}", attempt, llmResponse);

          // Clean response - remove markdown code blocks if present
          String cleanedResponse = cleanJsonResponse(llmResponse);
          log.debug("Cleaned Response: {}", cleanedResponse);

          // Parse JSON response
          JsonNode jsonNode = objectMapper.readTree(cleanedResponse);

          String generatedFilter = jsonNode.get("filter").asText();
          log.info("Generated filter (attempt {}): {}", attempt, generatedFilter);

          // Validate the generated filter
          ValidationResult validation = validateBpfFilter(generatedFilter, pcapFile);

          if (validation.isValid()) {
            // Filter is valid, return it
            log.info("Filter validation successful on attempt {}", attempt);
            response =
                FilterGenerationResponse.builder()
                    .filter(generatedFilter)
                    .explanation(jsonNode.get("explanation").asText())
                    .confidence(jsonNode.get("confidence").asDouble())
                    .suggestions(parseSuggestions(jsonNode))
                    .build();
            break; // Success, exit retry loop
          } else {
            // Filter is invalid, prepare retry with feedback
            lastValidationError = validation.getErrorMessage();
            log.warn("Generated filter is invalid (attempt {}): {}", attempt, lastValidationError);

            if (attempt < MAX_GENERATION_RETRIES) {
              // Provide feedback to LLM for retry
              userPrompt =
                  String.format(
                      "Create a BPF filter for: %s\n\n"
                          + "IMPORTANT: Your previous attempt generated an INVALID filter: \"%s\"\n"
                          + "Validation error: %s\n"
                          + "Please generate a DIFFERENT, valid BPF filter that correctly addresses the query.",
                      naturalLanguageQuery, generatedFilter, lastValidationError);
            }
          }

        } catch (JsonProcessingException e) {
          log.error("Failed to parse LLM response on attempt {}", attempt, e);
          lastValidationError = "LLM returned invalid JSON format";
          if (attempt < MAX_GENERATION_RETRIES) {
            userPrompt =
                String.format(
                    "Create a BPF filter for: %s\n\n"
                        + "IMPORTANT: Your previous response was not valid JSON. "
                        + "Please respond with ONLY valid JSON in the exact format specified.",
                    naturalLanguageQuery);
          }
        } catch (Exception e) {
          log.error("Error processing LLM response on attempt {}", attempt, e);
          lastValidationError = "Error processing LLM response: " + e.getMessage();
        }
      }

      // Check if we got a valid response
      if (response != null) {
        return response;
      } else {
        // All retries failed
        log.error(
            "Failed to generate valid filter after {} attempts. Last error: {}",
            MAX_GENERATION_RETRIES,
            lastValidationError);
        throw new RuntimeException(
            String.format(
                "LLM was unable to generate a valid BPF filter after %d attempts. "
                    + "Last validation error: %s. Please try rephrasing your query or use a more specific request.",
                MAX_GENERATION_RETRIES, lastValidationError));
      }

    } catch (Exception e) {
      log.error("Error generating filter", e);
      throw new RuntimeException("Failed to generate filter: " + e.getMessage(), e);
    } finally {
      // Clean up temporary file
      if (pcapFile != null && pcapFile.exists()) {
        pcapFile.delete();
      }
    }
  }

  /** Execute a filter on a PCAP file and return matching packets with pagination */
  public FilterExecutionResponse executeFilter(
      UUID fileId, String filterExpression, int page, int pageSize) {
    log.info(
        "Executing filter on file {}: {} (page: {}, pageSize: {})",
        fileId,
        filterExpression,
        page,
        pageSize);

    long startTime = System.currentTimeMillis();
    FileEntity fileEntity = fileService.getFileById(fileId);

    File tempFile = null;
    try {
      // Download PCAP file to temporary location
      tempFile = Files.createTempFile("pcap-filter-", ".pcap").toFile();
      storageService.downloadFileToLocal(fileEntity.getMinioPath(), tempFile);

      // Validate filter BEFORE execution
      ValidationResult validation = validateBpfFilter(filterExpression, tempFile);
      if (!validation.isValid()) {
        log.error("Invalid BPF filter provided for execution: {}", filterExpression);
        throw new IllegalArgumentException(
            String.format(
                "Invalid BPF filter syntax. %s\n\n"
                    + "The filter '%s' cannot be executed. "
                    + "Please check the BPF syntax and try again. "
                    + "Common valid filters: 'tcp port 80', 'udp port 53', 'host 192.168.1.1', 'icmp'",
                validation.getErrorMessage(), filterExpression));
      }

      // Collect all matching packets (up to a reasonable limit)
      List<PacketDto> allPackets = filterPackets(tempFile, filterExpression, 10000);
      int totalMatches = allPackets.size();

      // Calculate pagination
      int totalPages = (int) Math.ceil((double) totalMatches / pageSize);
      int startIndex = (page - 1) * pageSize;
      int endIndex = Math.min(startIndex + pageSize, totalMatches);

      // Get packets for current page
      List<PacketDto> pagePackets =
          startIndex < totalMatches ? allPackets.subList(startIndex, endIndex) : List.of();

      long executionTime = System.currentTimeMillis() - startTime;

      log.info(
          "Filter execution completed: {} total matches, returning {} for page {}/{}",
          totalMatches,
          pagePackets.size(),
          page,
          totalPages);

      return FilterExecutionResponse.builder()
          .packets(pagePackets)
          .totalMatches(totalMatches)
          .executionTime(executionTime)
          .page(page)
          .pageSize(pageSize)
          .totalPages(totalPages)
          .build();

    } catch (IllegalArgumentException e) {
      // Re-throw validation errors without wrapping
      throw e;
    } catch (Exception e) {
      log.error("Error executing filter", e);
      throw new RuntimeException("Failed to execute filter: " + e.getMessage(), e);
    } finally {
      // Clean up temporary file
      if (tempFile != null && tempFile.exists()) {
        tempFile.delete();
      }
    }
  }

  /** Filter packets from PCAP file using BPF filter with a maximum limit */
  private List<PacketDto> filterPackets(File pcapFile, String bpfFilter, int maxPackets) {
    List<PacketDto> matchedPackets = new ArrayList<>();
    int packetCount = 0;

    try (PcapHandle handle = Pcaps.openOffline(pcapFile.getAbsolutePath())) {

      // Apply BPF filter
      if (bpfFilter != null && !bpfFilter.trim().isEmpty()) {
        try {
          handle.setFilter(bpfFilter, BpfProgram.BpfCompileMode.OPTIMIZE);
          log.info("BPF filter applied successfully: {}", bpfFilter);
        } catch (Exception e) {
          log.error("Invalid BPF filter: {}", bpfFilter, e);
          throw new IllegalArgumentException("Invalid BPF filter syntax: " + e.getMessage());
        }
      }

      Packet packet;
      while ((packet = handle.getNextPacket()) != null && packetCount < maxPackets) {
        try {
          PacketDto packetDto = convertToPacketDto(packet, handle, packetCount);
          if (packetDto != null) {
            matchedPackets.add(packetDto);
            packetCount++;
          }
        } catch (Exception e) {
          log.warn("Error processing packet {}: {}", packetCount, e.getMessage());
        }
      }

      if (packetCount >= maxPackets) {
        log.info("Reached maximum packet limit of {}", maxPackets);
      }

    } catch (PcapNativeException | NotOpenException e) {
      log.error("Error reading PCAP file", e);
      throw new RuntimeException("Failed to read PCAP file: " + e.getMessage(), e);
    }

    return matchedPackets;
  }

  /** Convert pcap4j Packet to PacketDto */
  private PacketDto convertToPacketDto(Packet packet, PcapHandle handle, int packetNumber) {
    try {
      // Get timestamp
      long timestampMs = handle.getTimestamp().getTime();

      // Extract IP packet
      IpPacket ipPacket = packet.get(IpPacket.class);
      if (ipPacket == null) {
        return null; // Skip non-IP packets for simplicity
      }

      String srcIp = ipPacket.getHeader().getSrcAddr().getHostAddress();
      String dstIp = ipPacket.getHeader().getDstAddr().getHostAddress();

      Integer srcPort = null;
      Integer dstPort = null;
      String protocolName = "IP";
      String layer = "network";
      List<String> flags = new ArrayList<>();

      // Check for TCP
      TcpPacket tcpPacket = ipPacket.get(TcpPacket.class);
      if (tcpPacket != null) {
        protocolName = "TCP";
        layer = "transport";
        srcPort = tcpPacket.getHeader().getSrcPort().valueAsInt();
        dstPort = tcpPacket.getHeader().getDstPort().valueAsInt();

        // Extract TCP flags
        TcpPacket.TcpHeader tcpHeader = tcpPacket.getHeader();
        if (tcpHeader.getSyn()) flags.add("SYN");
        if (tcpHeader.getAck()) flags.add("ACK");
        if (tcpHeader.getFin()) flags.add("FIN");
        if (tcpHeader.getRst()) flags.add("RST");
        if (tcpHeader.getPsh()) flags.add("PSH");
        if (tcpHeader.getUrg()) flags.add("URG");

        // Check for application layer protocols
        if (srcPort == 80 || dstPort == 80) {
          protocolName = "HTTP";
          layer = "application";
        } else if (srcPort == 443 || dstPort == 443) {
          protocolName = "HTTPS";
          layer = "application";
        } else if (srcPort == 22 || dstPort == 22) {
          protocolName = "SSH";
          layer = "application";
        }
      }
      // Check for UDP
      else if (ipPacket.get(UdpPacket.class) != null) {
        UdpPacket udpPacket = ipPacket.get(UdpPacket.class);
        protocolName = "UDP";
        layer = "transport";
        srcPort = udpPacket.getHeader().getSrcPort().valueAsInt();
        dstPort = udpPacket.getHeader().getDstPort().valueAsInt();

        // Check for DNS
        if (srcPort == 53 || dstPort == 53) {
          protocolName = "DNS";
          layer = "application";
        }
      }
      // Check for ICMP
      else if (ipPacket.get(IcmpV4CommonPacket.class) != null) {
        protocolName = "ICMP";
        layer = "network";
      }

      // Get payload (limited to first 200 bytes)
      String payload = "";
      byte[] rawData = packet.getRawData();
      if (rawData != null && rawData.length > 0) {
        int payloadLength = Math.min(rawData.length, 200);
        payload = new String(rawData, 0, payloadLength);
        // Replace non-printable characters
        payload = payload.replaceAll("[^\\x20-\\x7E\\n\\r\\t]", ".");
      }

      return PacketDto.builder()
          .id(String.valueOf(packetNumber))
          .timestamp(timestampMs)
          .source(PacketDto.NetworkEndpoint.builder().ip(srcIp).port(srcPort).build())
          .destination(PacketDto.NetworkEndpoint.builder().ip(dstIp).port(dstPort).build())
          .protocol(PacketDto.Protocol.builder().layer(layer).name(protocolName).build())
          .size(packet.length())
          .payload(payload)
          .flags(flags.isEmpty() ? null : flags)
          .build();

    } catch (Exception e) {
      log.warn("Error converting packet: {}", e.getMessage());
      return null;
    }
  }

  /** Parse suggestions from JSON response */
  private List<String> parseSuggestions(JsonNode jsonNode) {
    List<String> suggestions = new ArrayList<>();
    JsonNode suggestionsNode = jsonNode.get("suggestions");

    if (suggestionsNode != null && suggestionsNode.isArray()) {
      suggestionsNode.forEach(node -> suggestions.add(node.asText()));
    }

    return suggestions.isEmpty() ? null : suggestions;
  }

  /** Clean JSON response by removing markdown code blocks if present */
  private String cleanJsonResponse(String response) {
    if (response == null) {
      return null;
    }

    String cleaned = response.trim();

    // Remove markdown code blocks (```json ... ``` or ``` ... ```)
    if (cleaned.startsWith("```")) {
      // Find the first newline after opening ```
      int firstNewline = cleaned.indexOf('\n');
      if (firstNewline != -1) {
        cleaned = cleaned.substring(firstNewline + 1);
      }

      // Remove closing ```
      if (cleaned.endsWith("```")) {
        cleaned = cleaned.substring(0, cleaned.lastIndexOf("```"));
      }

      cleaned = cleaned.trim();
    }

    return cleaned;
  }

  /** Inner class to hold validation results */
  private static class ValidationResult {
    private final boolean valid;
    private final String errorMessage;

    public ValidationResult(boolean valid, String errorMessage) {
      this.valid = valid;
      this.errorMessage = errorMessage;
    }

    public boolean isValid() {
      return valid;
    }

    public String getErrorMessage() {
      return errorMessage;
    }
  }
}
