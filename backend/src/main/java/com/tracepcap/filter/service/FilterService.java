package com.tracepcap.filter.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.service.FileService;
import com.tracepcap.file.service.StorageService;
import com.tracepcap.filter.dto.*;
import com.tracepcap.story.service.LlmClient;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.util.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/** Service for filter generation and execution using tshark display filters. */
@Slf4j
@Service
@RequiredArgsConstructor
public class FilterService {

  private final LlmClient llmClient;
  private final FileService fileService;
  private final StorageService storageService;
  private final ObjectMapper objectMapper;

  private static final int MAX_PACKETS = 100;
  private static final int MAX_GENERATION_RETRIES = 3;

  /**
   * Validate a Wireshark display filter by running tshark against the PCAP file.
   * tshark exits non-zero and prints to stderr when the filter expression is invalid.
   */
  private ValidationResult validateDisplayFilter(String displayFilter, File pcapFile) {
    if (displayFilter == null || displayFilter.trim().isEmpty()) {
      return new ValidationResult(false, "Filter cannot be empty");
    }

    try {
      ProcessBuilder pb = new ProcessBuilder(
          "tshark", "-r", pcapFile.getAbsolutePath(),
          "-Y", displayFilter.trim(),
          "-c", "1");
      pb.redirectErrorStream(true);
      Process process = pb.start();

      StringBuilder output = new StringBuilder();
      try (BufferedReader reader =
          new BufferedReader(new InputStreamReader(process.getInputStream()))) {
        String line;
        while ((line = reader.readLine()) != null) {
          output.append(line).append('\n');
        }
      }

      int exitCode = process.waitFor();
      if (exitCode == 0) {
        return new ValidationResult(true, null);
      }

      // Extract the first error line from tshark output
      String errorMsg = output.toString().trim();
      String firstLine = errorMsg.contains("\n") ? errorMsg.substring(0, errorMsg.indexOf('\n')) : errorMsg;
      log.warn("Display filter validation failed for '{}': {}", displayFilter, firstLine);
      return new ValidationResult(false, "Invalid filter syntax: " + firstLine);

    } catch (Exception e) {
      log.error("Error validating display filter", e);
      return new ValidationResult(false, "Unable to validate filter: " + e.getMessage());
    }
  }

  /** Generate a Wireshark display filter from natural language using LLM with validation and retry */
  public FilterGenerationResponse generateFilter(UUID fileId, String naturalLanguageQuery) {
    log.info("Generating filter for file {} with query: {}", fileId, naturalLanguageQuery);

    FileEntity fileEntity = fileService.getFileById(fileId);
    File pcapFile = null;

    try {
      pcapFile = Files.createTempFile("pcap-validation-", ".pcap").toFile();
      storageService.downloadFileToLocal(fileEntity.getMinioPath(), pcapFile);

      String systemPrompt =
          """
                    You are an expert network security analyst specialized in creating Wireshark display filters.
                    Your task is to convert natural language queries into valid Wireshark display filter syntax.

                    Display Filter Syntax Reference:
                    - Protocols: tcp, udp, icmp, dns, http, tls, arp, ip, ipv6
                    - Fields: ip.src, ip.dst, tcp.srcport, tcp.dstport, udp.srcport, udp.dstport
                    - Comparisons: ==, !=, >, <, >=, <=, contains, matches
                    - Logical operators: &&, ||, !
                    - Membership: ip.src in {192.168.0.0/16 10.0.0.0/8}

                    Common Examples:
                    - HTTP traffic: "http"
                    - HTTPS/TLS: "tls"
                    - DNS queries: "dns"
                    - Traffic from specific IP: "ip.src == 192.168.1.1"
                    - SSH connections: "tcp.port == 22"
                    - All traffic to/from IP: "ip.addr == 192.168.1.1"
                    - Large packets: "frame.len > 1000"
                    - TCP SYN packets: "tcp.flags.syn == 1 && tcp.flags.ack == 0"

                    Respond ONLY with valid JSON in this exact format (no markdown, no extra text):
                    {
                      "filter": "the Wireshark display filter string",
                      "explanation": "clear explanation of what this filter does",
                      "confidence": 0.95,
                      "suggestions": ["optional suggestion 1", "optional suggestion 2"]
                    }

                    The confidence should be between 0.0 and 1.0 based on how certain you are about the filter.
                    Include suggestions only if there are alternative approaches or refinements.
                    """;

      String userPrompt = String.format("Create a Wireshark display filter for: %s", naturalLanguageQuery);
      FilterGenerationResponse response = null;
      String lastValidationError = null;

      for (int attempt = 1; attempt <= MAX_GENERATION_RETRIES; attempt++) {
        log.info("Filter generation attempt {}/{}", attempt, MAX_GENERATION_RETRIES);

        try {
          String llmResponse = llmClient.generateCompletion(systemPrompt, userPrompt);
          log.debug("LLM Response (attempt {}): {}", attempt, llmResponse);

          String cleanedResponse = cleanJsonResponse(llmResponse);
          log.debug("Cleaned Response: {}", cleanedResponse);

          JsonNode jsonNode = objectMapper.readTree(cleanedResponse);
          String generatedFilter = jsonNode.get("filter").asText();
          log.info("Generated filter (attempt {}): {}", attempt, generatedFilter);

          ValidationResult validation = validateDisplayFilter(generatedFilter, pcapFile);

          if (validation.isValid()) {
            log.info("Filter validation successful on attempt {}", attempt);
            response =
                FilterGenerationResponse.builder()
                    .filter(generatedFilter)
                    .explanation(jsonNode.get("explanation").asText())
                    .confidence(jsonNode.get("confidence").asDouble())
                    .suggestions(parseSuggestions(jsonNode))
                    .build();
            break;
          } else {
            lastValidationError = validation.getErrorMessage();
            log.warn("Generated filter is invalid (attempt {}): {}", attempt, lastValidationError);

            if (attempt < MAX_GENERATION_RETRIES) {
              userPrompt =
                  String.format(
                      "Create a Wireshark display filter for: %s\n\n"
                          + "IMPORTANT: Your previous attempt generated an INVALID filter: \"%s\"\n"
                          + "Validation error: %s\n"
                          + "Please generate a DIFFERENT, valid Wireshark display filter that correctly addresses the query.",
                      naturalLanguageQuery, generatedFilter, lastValidationError);
            }
          }

        } catch (JsonProcessingException e) {
          log.error("Failed to parse LLM response on attempt {}", attempt, e);
          lastValidationError = "LLM returned invalid JSON format";
          if (attempt < MAX_GENERATION_RETRIES) {
            userPrompt =
                String.format(
                    "Create a Wireshark display filter for: %s\n\n"
                        + "IMPORTANT: Your previous response was not valid JSON. "
                        + "Please respond with ONLY valid JSON in the exact format specified.",
                    naturalLanguageQuery);
          }
        } catch (Exception e) {
          log.error("Error processing LLM response on attempt {}", attempt, e);
          lastValidationError = "Error processing LLM response: " + e.getMessage();
        }
      }

      if (response != null) {
        return response;
      } else {
        log.error(
            "Failed to generate valid filter after {} attempts. Last error: {}",
            MAX_GENERATION_RETRIES,
            lastValidationError);
        throw new RuntimeException(
            String.format(
                "LLM was unable to generate a valid display filter after %d attempts. "
                    + "Last validation error: %s. Please try rephrasing your query or use a more specific request.",
                MAX_GENERATION_RETRIES, lastValidationError));
      }

    } catch (Exception e) {
      log.error("Error generating filter", e);
      throw new RuntimeException("Failed to generate filter: " + e.getMessage(), e);
    } finally {
      if (pcapFile != null && pcapFile.exists()) {
        pcapFile.delete();
      }
    }
  }

  /** Execute a Wireshark display filter on a PCAP file and return matching packets with pagination */
  public FilterExecutionResponse executeFilter(
      UUID fileId, String filterExpression, int page, int pageSize) {
    log.info(
        "Executing filter on file {}: {} (page: {}, pageSize: {})",
        fileId, filterExpression, page, pageSize);

    long startTime = System.currentTimeMillis();
    FileEntity fileEntity = fileService.getFileById(fileId);

    File tempFile = null;
    try {
      tempFile = Files.createTempFile("pcap-filter-", ".pcap").toFile();
      storageService.downloadFileToLocal(fileEntity.getMinioPath(), tempFile);

      ValidationResult validation = validateDisplayFilter(filterExpression, tempFile);
      if (!validation.isValid()) {
        log.error("Invalid display filter provided for execution: {}", filterExpression);
        throw new IllegalArgumentException(
            String.format(
                "Invalid filter syntax. %s\n\n"
                    + "The filter '%s' cannot be executed. "
                    + "Please check the Wireshark display filter syntax and try again. "
                    + "Common valid filters: 'tcp', 'udp port 53', 'ip.addr == 192.168.1.1', 'http', 'dns'",
                validation.getErrorMessage(), filterExpression));
      }

      List<PacketDto> allPackets = filterPackets(tempFile, filterExpression, 10000);
      int totalMatches = allPackets.size();

      int totalPages = (int) Math.ceil((double) totalMatches / pageSize);
      int startIndex = (page - 1) * pageSize;
      int endIndex = Math.min(startIndex + pageSize, totalMatches);

      List<PacketDto> pagePackets =
          startIndex < totalMatches ? allPackets.subList(startIndex, endIndex) : List.of();

      long executionTime = System.currentTimeMillis() - startTime;

      log.info(
          "Filter execution completed: {} total matches, returning {} for page {}/{}",
          totalMatches, pagePackets.size(), page, totalPages);

      return FilterExecutionResponse.builder()
          .packets(pagePackets)
          .totalMatches(totalMatches)
          .executionTime(executionTime)
          .page(page)
          .pageSize(pageSize)
          .totalPages(totalPages)
          .build();

    } catch (IllegalArgumentException e) {
      throw e;
    } catch (Exception e) {
      log.error("Error executing filter", e);
      throw new RuntimeException("Failed to execute filter: " + e.getMessage(), e);
    } finally {
      if (tempFile != null && tempFile.exists()) {
        tempFile.delete();
      }
    }
  }

  /** Run tshark with a display filter and collect matching packets up to maxPackets. */
  private List<PacketDto> filterPackets(File pcapFile, String displayFilter, int maxPackets) {
    List<PacketDto> matchedPackets = new ArrayList<>();

    // Fields: epoch | len | ip.src | ip.dst | tcp.sport | tcp.dport | udp.sport | udp.dport |
    //         protocol | info | tcp.flags.syn | tcp.flags.ack | tcp.flags.fin |
    //         tcp.flags.rst | tcp.flags.psh | tcp.flags.urg | tcp.payload | udp.payload
    ProcessBuilder pb = new ProcessBuilder(
        "tshark", "-r", pcapFile.getAbsolutePath(),
        "-Y", displayFilter,
        "-T", "fields",
        "-E", "separator=|",
        "-e", "frame.time_epoch",
        "-e", "frame.len",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        "-e", "_ws.col.Protocol",
        "-e", "_ws.col.Info",
        "-e", "tcp.flags.syn",
        "-e", "tcp.flags.ack",
        "-e", "tcp.flags.fin",
        "-e", "tcp.flags.rst",
        "-e", "tcp.flags.push",
        "-e", "tcp.flags.urg",
        "-e", "tcp.payload",
        "-e", "udp.payload");
    pb.redirectError(ProcessBuilder.Redirect.DISCARD);

    try {
      Process process = pb.start();
      int packetNumber = 0;

      try (BufferedReader reader =
          new BufferedReader(new InputStreamReader(process.getInputStream()))) {
        String line;
        while ((line = reader.readLine()) != null && packetNumber < maxPackets) {
          if (line.isEmpty()) continue;
          String[] f = line.split("\\|", -1);
          if (f.length < 10) continue;

          packetNumber++;
          PacketDto dto = parsePacketLine(f, packetNumber);
          if (dto != null) matchedPackets.add(dto);
        }
      }

      process.waitFor();
      if (packetNumber >= maxPackets) {
        log.info("Reached maximum packet limit of {}", maxPackets);
      }

    } catch (Exception e) {
      log.error("Error filtering packets with tshark", e);
      throw new RuntimeException("Failed to filter packets: " + e.getMessage(), e);
    }

    return matchedPackets;
  }

  private PacketDto parsePacketLine(String[] f, int packetNumber) {
    try {
      double epochSec = f[0].isEmpty() ? 0 : Double.parseDouble(f[0]);
      long timestampMs = (long) (epochSec * 1000);
      int frameLen = f[1].isEmpty() ? 0 : Integer.parseInt(f[1]);

      String srcIp = f[2].isEmpty() ? null : f[2];
      String dstIp = f[3].isEmpty() ? null : f[3];
      if (srcIp == null || dstIp == null) return null;

      Integer srcPort = null;
      Integer dstPort = null;
      if (!f[4].isEmpty()) {
        srcPort = Integer.parseInt(f[4]);
        dstPort = Integer.parseInt(f[5]);
      } else if (!f[6].isEmpty()) {
        srcPort = Integer.parseInt(f[6]);
        dstPort = Integer.parseInt(f[7]);
      }

      String protocolRaw = f[8].isEmpty() ? "OTHER" : f[8].toUpperCase();
      String info = f.length > 9 && !f[9].isEmpty() ? f[9] : protocolRaw;

      // TCP flags (indices 10–15)
      List<String> flags = new ArrayList<>();
      String[] flagNames = {"SYN", "ACK", "FIN", "RST", "PSH", "URG"};
      for (int i = 0; i < flagNames.length; i++) {
        if (f.length > 10 + i && "1".equals(f[10 + i])) flags.add(flagNames[i]);
      }

      // Payload as printable ASCII (indices 16 = tcp.payload, 17 = udp.payload)
      String payloadHex = null;
      if (f.length > 16 && !f[16].isEmpty()) payloadHex = f[16];
      else if (f.length > 17 && !f[17].isEmpty()) payloadHex = f[17];

      String payloadAscii = hexToAscii(payloadHex, 200);

      // Derive layer from protocol
      String proto = protocolRaw;
      String layer;
      if (proto.equals("HTTP") || proto.equals("HTTPS") || proto.equals("DNS")
          || proto.equals("SSH") || proto.equals("FTP") || proto.equals("SMTP")
          || proto.equals("IMAP") || proto.equals("POP") || proto.equals("TLS")) {
        layer = "application";
      } else if (proto.equals("TCP") || proto.equals("UDP")) {
        layer = "transport";
      } else {
        layer = "network";
      }

      return PacketDto.builder()
          .id(String.valueOf(packetNumber))
          .timestamp(timestampMs)
          .source(PacketDto.NetworkEndpoint.builder().ip(srcIp).port(srcPort).build())
          .destination(PacketDto.NetworkEndpoint.builder().ip(dstIp).port(dstPort).build())
          .protocol(PacketDto.Protocol.builder().layer(layer).name(proto).build())
          .size(frameLen)
          .payload(payloadAscii)
          .flags(flags.isEmpty() ? null : flags)
          .build();

    } catch (Exception e) {
      log.warn("Error parsing packet line: {}", e.getMessage());
      return null;
    }
  }

  /**
   * Convert tshark colon-separated hex payload to a printable ASCII string (non-printable → '.'),
   * limited to {@code maxBytes} bytes.
   */
  private String hexToAscii(String tsharkHex, int maxBytes) {
    if (tsharkHex == null || tsharkHex.isEmpty()) return "";
    String plain = tsharkHex.replace(":", "");
    int byteCount = Math.min(plain.length() / 2, maxBytes);
    StringBuilder sb = new StringBuilder(byteCount);
    for (int i = 0; i < byteCount * 2; i += 2) {
      int b = (Character.digit(plain.charAt(i), 16) << 4)
          | Character.digit(plain.charAt(i + 1), 16);
      sb.append((b >= 0x20 && b <= 0x7e) ? (char) b : '.');
    }
    return sb.toString();
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
    if (response == null) return null;
    String cleaned = response.trim();
    if (cleaned.startsWith("```")) {
      int firstNewline = cleaned.indexOf('\n');
      if (firstNewline != -1) cleaned = cleaned.substring(firstNewline + 1);
      if (cleaned.endsWith("```")) cleaned = cleaned.substring(0, cleaned.lastIndexOf("```"));
      cleaned = cleaned.trim();
    }
    return cleaned;
  }

  private static class ValidationResult {
    private final boolean valid;
    private final String errorMessage;

    ValidationResult(boolean valid, String errorMessage) {
      this.valid = valid;
      this.errorMessage = errorMessage;
    }

    boolean isValid() { return valid; }
    String getErrorMessage() { return errorMessage; }
  }
}
