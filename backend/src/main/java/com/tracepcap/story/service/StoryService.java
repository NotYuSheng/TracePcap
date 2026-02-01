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
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Service for generating and managing network traffic stories using LLM
 */
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

        // Check if story already exists for this file
        Optional<StoryEntity> existingStory = storyRepository.findFirstByFileIdOrderByGeneratedAtDesc(fileId);
        if (existingStory.isPresent() && existingStory.get().getStatus() == StoryEntity.StoryStatus.COMPLETED) {
            log.info("Story already exists for file: {}, returning cached version", fileId);
            try {
                return objectMapper.readValue(existingStory.get().getContent(), StoryResponse.class);
            } catch (Exception e) {
                log.warn("Failed to parse existing story, regenerating", e);
                // Continue to regenerate if parsing fails
            }
        }

        // Verify file exists
        FileEntity file = fileRepository.findById(fileId)
                .orElseThrow(() -> new ResourceNotFoundException("File not found: " + fileId));

        // Get analysis results
        AnalysisResultEntity analysis = analysisResultRepository.findByFileId(fileId)
                .orElseThrow(() -> new ResourceNotFoundException("Analysis not found for file: " + fileId));

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
            StoryEntity story = StoryEntity.builder()
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
            StoryEntity failedStory = StoryEntity.builder()
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
        StoryEntity story = storyRepository.findById(storyId)
                .orElseThrow(() -> new ResourceNotFoundException("Story not found: " + storyId));

        try {
            StoryResponse response = objectMapper.readValue(story.getContent(), StoryResponse.class);
            return response;
        } catch (Exception e) {
            log.error("Failed to parse story content", e);
            throw new RuntimeException("Failed to parse story content: " + e.getMessage(), e);
        }
    }

    /**
     * Generate story content using LLM
     */
    private String generateStoryContent(FileEntity file, AnalysisResultEntity analysis,
                                         List<ConversationEntity> conversations) {

        String systemPrompt = buildSystemPrompt();
        String userPrompt = buildUserPrompt(file, analysis, conversations);

        return llmClient.generateCompletion(systemPrompt, userPrompt);
    }

    /**
     * Build system prompt for LLM
     */
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
            """;
    }

    /**
     * Build user prompt with analysis data
     */
    private String buildUserPrompt(FileEntity file, AnalysisResultEntity analysis,
                                     List<ConversationEntity> conversations) {

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

        if (!conversations.isEmpty()) {
            prompt.append("## Conversations Detected\n");
            for (int i = 0; i < Math.min(10, conversations.size()); i++) {
                ConversationEntity conv = conversations.get(i);
                prompt.append(String.format("%d. %s:%d <-> %s:%d (%s, %d packets, %d bytes)\n",
                        i + 1,
                        conv.getSrcIp(), conv.getSrcPort(),
                        conv.getDstIp(), conv.getDstPort(),
                        conv.getProtocol(),
                        conv.getPacketCount(),
                        conv.getTotalBytes()));
            }
            prompt.append("\n");
        }

        prompt.append("Generate a detailed story analyzing this network traffic. ");
        prompt.append("Include narrative sections, highlights of interesting findings, ");
        prompt.append("and a timeline of key events. Respond ONLY with valid JSON.");

        return prompt.toString();
    }

    /**
     * Parse LLM response into StoryResponse
     */
    private StoryResponse parseStoryContent(String content, UUID storyId, UUID fileId) {
        try {
            // Extract JSON from response (in case LLM adds extra text)
            String jsonContent = extractJson(content);

            // Parse JSON
            Map<String, Object> data = objectMapper.readValue(jsonContent, new TypeReference<>() {});

            // Parse narrative sections
            List<NarrativeSection> narrative = parseNarrativeSections(data.get("narrative"));

            // Parse highlights
            List<Highlight> highlights = parseHighlights(data.get("highlights"));

            // Parse timeline
            List<StoryTimelineEvent> timeline = parseTimeline(data.get("timeline"));

            return StoryResponse.builder()
                    .id(storyId.toString())
                    .fileId(fileId.toString())
                    .generatedAt(System.currentTimeMillis())
                    .narrative(narrative)
                    .highlights(highlights)
                    .timeline(timeline)
                    .build();

        } catch (Exception e) {
            log.error("Failed to parse LLM response", e);
            throw new RuntimeException("Failed to parse LLM response: " + e.getMessage(), e);
        }
    }

    /**
     * Extract JSON from LLM response
     */
    private String extractJson(String content) {
        // Find first { and last }
        int start = content.indexOf('{');
        int end = content.lastIndexOf('}');

        if (start >= 0 && end > start) {
            return content.substring(start, end + 1);
        }

        return content;
    }

    /**
     * Parse narrative sections from JSON
     */
    @SuppressWarnings("unchecked")
    private List<NarrativeSection> parseNarrativeSections(Object data) {
        if (data == null) return new ArrayList<>();

        List<Map<String, Object>> sections = (List<Map<String, Object>>) data;
        return sections.stream().map(section -> {
            Map<String, Object> relatedData = (Map<String, Object>) section.getOrDefault("relatedData", new HashMap<>());

            return NarrativeSection.builder()
                    .title((String) section.get("title"))
                    .content((String) section.get("content"))
                    .type(NarrativeSection.SectionType.valueOf((String) section.getOrDefault("type", "detail")))
                    .relatedData(NarrativeSection.RelatedData.builder()
                            .packets(convertToStringList(relatedData.get("packets")))
                            .conversations(convertToStringList(relatedData.get("conversations")))
                            .hosts(convertToStringList(relatedData.get("hosts")))
                            .build())
                    .build();
        }).collect(Collectors.toList());
    }

    /**
     * Parse highlights from JSON
     */
    @SuppressWarnings("unchecked")
    private List<Highlight> parseHighlights(Object data) {
        if (data == null) return new ArrayList<>();

        List<Map<String, Object>> highlights = (List<Map<String, Object>>) data;
        return highlights.stream().map(h -> {
            Object timestamp = h.get("timestamp");
            Long ts = timestamp != null ? ((Number) timestamp).longValue() : null;

            return Highlight.builder()
                    .id((String) h.get("id"))
                    .type(Highlight.HighlightType.valueOf((String) h.getOrDefault("type", "info")))
                    .title((String) h.get("title"))
                    .description((String) h.get("description"))
                    .timestamp(ts)
                    .build();
        }).collect(Collectors.toList());
    }

    /**
     * Parse timeline events from JSON
     */
    @SuppressWarnings("unchecked")
    private List<StoryTimelineEvent> parseTimeline(Object data) {
        if (data == null) return new ArrayList<>();

        List<Map<String, Object>> events = (List<Map<String, Object>>) data;
        return events.stream().map(event -> {
            Map<String, Object> relatedData = (Map<String, Object>) event.getOrDefault("relatedData", new HashMap<>());
            Object timestamp = event.get("timestamp");

            return StoryTimelineEvent.builder()
                    .timestamp(timestamp != null ? ((Number) timestamp).longValue() : null)
                    .title((String) event.get("title"))
                    .description((String) event.get("description"))
                    .type(StoryTimelineEvent.EventType.valueOf((String) event.getOrDefault("type", "normal")))
                    .relatedData(StoryTimelineEvent.RelatedData.builder()
                            .packets(convertToStringList(relatedData.get("packets")))
                            .conversations(convertToStringList(relatedData.get("conversations")))
                            .build())
                    .build();
        }).collect(Collectors.toList());
    }

    /**
     * Convert various types to string list (handles both strings and objects)
     */
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
                .map(item -> {
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
}
