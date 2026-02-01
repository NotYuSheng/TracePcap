package com.tracepcap.analysis.service;

import com.tracepcap.analysis.dto.AnalysisSummaryResponse;
import com.tracepcap.analysis.dto.ConversationResponse;
import com.tracepcap.analysis.dto.ProtocolStatsResponse;
import com.tracepcap.analysis.entity.AnalysisResultEntity;
import com.tracepcap.analysis.entity.ConversationEntity;
import com.tracepcap.analysis.repository.AnalysisResultRepository;
import com.tracepcap.analysis.repository.ConversationRepository;
import com.tracepcap.common.exception.ResourceNotFoundException;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.repository.FileRepository;
import com.tracepcap.file.service.StorageService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.File;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class AnalysisService {

    private final AnalysisResultRepository analysisResultRepository;
    private final ConversationRepository conversationRepository;
    private final FileRepository fileRepository;
    private final StorageService storageService;
    private final PcapParserService pcapParserService;

    @Transactional
    public void analyzeFile(UUID fileId) {
        log.info("Starting analysis for file: {}", fileId);

        FileEntity file = fileRepository.findById(fileId)
                .orElseThrow(() -> new ResourceNotFoundException("File not found: " + fileId));

        // Check if already analyzed
        if (analysisResultRepository.existsByFileId(fileId)) {
            log.info("File {} already analyzed, skipping", fileId);
            return;
        }

        try {
            // Create initial analysis record
            AnalysisResultEntity analysis = AnalysisResultEntity.builder()
                    .file(file)
                    .status(AnalysisResultEntity.AnalysisStatus.IN_PROGRESS)
                    .build();
            analysis = analysisResultRepository.save(analysis);

            // Download file from MinIO to temp location
            File tempFile = File.createTempFile("pcap-", ".pcap");
            storageService.downloadFileToLocal(file.getMinioPath(), tempFile);

            // Parse PCAP file
            PcapParserService.PcapAnalysisResult parseResult = pcapParserService.analyzePcapFile(tempFile);

            // Update analysis results
            analysis.setPacketCount(parseResult.getPacketCount());
            analysis.setTotalBytes(parseResult.getTotalBytes());
            analysis.setStartTime(parseResult.getStartTime());
            analysis.setEndTime(parseResult.getEndTime());

            if (parseResult.getStartTime() != null && parseResult.getEndTime() != null) {
                Duration duration = Duration.between(parseResult.getStartTime(), parseResult.getEndTime());
                analysis.setDurationMs(duration.toMillis());
            }

            // Convert protocol counts to JSON format
            Map<String, Object> protocolStats = new HashMap<>();
            parseResult.getProtocolCounts().forEach((protocol, count) -> {
                Map<String, Object> stat = new HashMap<>();
                stat.put("packetCount", count);
                stat.put("bytes", parseResult.getProtocolBytes().getOrDefault(protocol, 0L));
                stat.put("percentage", (count.doubleValue() / parseResult.getPacketCount()) * 100);
                protocolStats.put(protocol, stat);
            });
            analysis.setProtocolStats(protocolStats);
            analysis.setStatus(AnalysisResultEntity.AnalysisStatus.COMPLETED);

            analysisResultRepository.save(analysis);

            // Save conversations
            for (PcapParserService.ConversationInfo convInfo : parseResult.getConversations()) {
                ConversationEntity conversation = ConversationEntity.builder()
                        .file(file)
                        .srcIp(convInfo.getSrcIp())
                        .srcPort(convInfo.getSrcPort())
                        .dstIp(convInfo.getDstIp())
                        .dstPort(convInfo.getDstPort())
                        .protocol(convInfo.getProtocol())
                        .packetCount(convInfo.getPacketCount())
                        .totalBytes(convInfo.getTotalBytes())
                        .startTime(convInfo.getStartTime())
                        .endTime(convInfo.getEndTime())
                        .build();
                conversationRepository.save(conversation);
            }

            // Update file status
            file.setStatus(com.tracepcap.file.entity.FileEntity.FileStatus.COMPLETED);
            file.setPacketCount(parseResult.getPacketCount() != null ? parseResult.getPacketCount().intValue() : null);
            file.setTotalBytes(parseResult.getTotalBytes());
            file.setStartTime(parseResult.getStartTime());
            file.setEndTime(parseResult.getEndTime());
            file.setDuration(analysis.getDurationMs());
            fileRepository.save(file);

            // Cleanup temp file
            tempFile.delete();

            log.info("Analysis completed for file: {}", fileId);

        } catch (Exception e) {
            log.error("Error analyzing file {}: {}", fileId, e.getMessage(), e);

            // Mark analysis as failed
            analysisResultRepository.findByFileId(fileId).ifPresent(analysis -> {
                analysis.setStatus(AnalysisResultEntity.AnalysisStatus.FAILED);
                analysis.setErrorMessage(e.getMessage());
                analysisResultRepository.save(analysis);
            });

            throw new RuntimeException("Failed to analyze file", e);
        }
    }

    @Transactional(readOnly = true)
    public AnalysisSummaryResponse getAnalysisSummary(UUID fileId) {
        AnalysisResultEntity analysis = analysisResultRepository.findByFileId(fileId)
                .orElseThrow(() -> new ResourceNotFoundException("Analysis not found for file: " + fileId));

        FileEntity file = analysis.getFile();

        // Convert time to Unix timestamps (milliseconds)
        Long startTimeMs = analysis.getStartTime() != null
                ? analysis.getStartTime().toInstant(java.time.ZoneOffset.UTC).toEpochMilli()
                : null;
        Long endTimeMs = analysis.getEndTime() != null
                ? analysis.getEndTime().toInstant(java.time.ZoneOffset.UTC).toEpochMilli()
                : null;
        Long uploadTimeMs = file.getUploadedAt() != null
                ? file.getUploadedAt().toInstant(java.time.ZoneOffset.UTC).toEpochMilli()
                : null;

        // Build protocol distribution
        List<AnalysisSummaryResponse.ProtocolStat> protocolDistribution = new ArrayList<>();
        if (analysis.getProtocolStats() != null) {
            analysis.getProtocolStats().forEach((protocol, statsObj) -> {
                @SuppressWarnings("unchecked")
                Map<String, Object> stats = (Map<String, Object>) statsObj;
                protocolDistribution.add(AnalysisSummaryResponse.ProtocolStat.builder()
                        .protocol(protocol)
                        .count(((Number) stats.get("packetCount")).longValue())
                        .bytes(stats.get("bytes") != null ? ((Number) stats.get("bytes")).longValue() : 0L)
                        .percentage((Double) stats.get("percentage"))
                        .build());
            });
        }

        // Get top conversations
        List<ConversationEntity> conversations = conversationRepository.findByFileId(fileId);
        List<AnalysisSummaryResponse.ConversationSummary> topConversations = conversations.stream()
                .sorted((a, b) -> Long.compare(b.getTotalBytes(), a.getTotalBytes()))
                .limit(10)
                .map(conv -> AnalysisSummaryResponse.ConversationSummary.builder()
                        .id(conv.getId().toString())
                        .srcIp(conv.getSrcIp())
                        .srcPort(conv.getSrcPort())
                        .dstIp(conv.getDstIp())
                        .dstPort(conv.getDstPort())
                        .protocol(conv.getProtocol())
                        .startTime(conv.getStartTime() != null
                                ? conv.getStartTime().toInstant(java.time.ZoneOffset.UTC).toEpochMilli()
                                : null)
                        .endTime(conv.getEndTime() != null
                                ? conv.getEndTime().toInstant(java.time.ZoneOffset.UTC).toEpochMilli()
                                : null)
                        .packetCount(conv.getPacketCount())
                        .totalBytes(conv.getTotalBytes())
                        .build())
                .collect(Collectors.toList());

        // Get unique hosts
        Set<String> uniqueIps = new HashSet<>();
        List<AnalysisSummaryResponse.UniqueHost> uniqueHosts = new ArrayList<>();
        conversations.forEach(conv -> {
            if (uniqueIps.add(conv.getSrcIp())) {
                uniqueHosts.add(AnalysisSummaryResponse.UniqueHost.builder()
                        .ip(conv.getSrcIp())
                        .port(conv.getSrcPort())
                        .build());
            }
            if (uniqueIps.add(conv.getDstIp())) {
                uniqueHosts.add(AnalysisSummaryResponse.UniqueHost.builder()
                        .ip(conv.getDstIp())
                        .port(conv.getDstPort())
                        .build());
            }
        });

        return AnalysisSummaryResponse.builder()
                .analysisId(analysis.getId())
                .fileId(file.getId().toString())
                .fileName(file.getFileName())
                .fileSize(file.getFileSize())
                .uploadTime(uploadTimeMs)
                .totalPackets(analysis.getPacketCount())
                .timeRange(startTimeMs != null && endTimeMs != null
                        ? List.of(startTimeMs, endTimeMs)
                        : List.of())
                .protocolDistribution(protocolDistribution)
                .topConversations(topConversations)
                .uniqueHosts(uniqueHosts)
                // Legacy fields
                .startTime(analysis.getStartTime())
                .endTime(analysis.getEndTime())
                .durationMs(analysis.getDurationMs())
                .status(analysis.getStatus().name())
                .errorMessage(analysis.getErrorMessage())
                .analyzedAt(analysis.getCreatedAt())
                .build();
    }

    @Transactional(readOnly = true)
    public ProtocolStatsResponse getProtocolStats(UUID fileId) {
        AnalysisResultEntity analysis = analysisResultRepository.findByFileId(fileId)
                .orElseThrow(() -> new ResourceNotFoundException("Analysis not found for file: " + fileId));

        Map<String, ProtocolStatsResponse.ProtocolStat> protocols = new HashMap<>();

        if (analysis.getProtocolStats() != null) {
            analysis.getProtocolStats().forEach((protocol, statsObj) -> {
                @SuppressWarnings("unchecked")
                Map<String, Object> stats = (Map<String, Object>) statsObj;

                protocols.put(protocol, ProtocolStatsResponse.ProtocolStat.builder()
                        .packetCount(((Number) stats.get("packetCount")).longValue())
                        .bytes(stats.get("bytes") != null ? ((Number) stats.get("bytes")).longValue() : 0L)
                        .percentage((Double) stats.get("percentage"))
                        .build());
            });
        }

        return ProtocolStatsResponse.builder()
                .fileId(fileId)
                .protocols(protocols)
                .build();
    }

    @Transactional(readOnly = true)
    public List<ConversationResponse> getConversations(UUID fileId) {
        List<ConversationEntity> conversations = conversationRepository.findByFileId(fileId);

        return conversations.stream()
                .map(conv -> {
                    Duration duration = Duration.between(conv.getStartTime(), conv.getEndTime());

                    return ConversationResponse.builder()
                            .conversationId(conv.getId())
                            .srcIp(conv.getSrcIp())
                            .srcPort(conv.getSrcPort())
                            .dstIp(conv.getDstIp())
                            .dstPort(conv.getDstPort())
                            .protocol(conv.getProtocol())
                            .packetCount(conv.getPacketCount())
                            .totalBytes(conv.getTotalBytes())
                            .startTime(conv.getStartTime())
                            .endTime(conv.getEndTime())
                            .durationMs(duration.toMillis())
                            .build();
                })
                .collect(Collectors.toList());
    }

    /**
     * Get analysis result entity by file ID (for status checking)
     * Returns null if analysis doesn't exist yet
     */
    @Transactional(readOnly = true)
    public AnalysisResultEntity getAnalysisResultByFileId(UUID fileId) {
        return analysisResultRepository.findByFileId(fileId).orElse(null);
    }
}
