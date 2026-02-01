package com.tracepcap.analysis.service;

import lombok.extern.slf4j.Slf4j;
import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.IpNumber;
import org.springframework.stereotype.Service;

import java.io.EOFException;
import java.io.File;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;
import java.util.concurrent.TimeoutException;

/**
 * Service for parsing PCAP files using Pcap4J
 */
@Slf4j
@Service
public class PcapParserService {

    public PcapAnalysisResult analyzePcapFile(File pcapFile) {
        log.info("Starting PCAP analysis for file: {}", pcapFile.getName());

        PcapAnalysisResult result = new PcapAnalysisResult();
        result.setProtocolCounts(new HashMap<>());
        result.setProtocolBytes(new HashMap<>());
        result.setConversations(new ArrayList<>());

        Map<String, ConversationInfo> conversationMap = new HashMap<>();

        try (PcapHandle handle = Pcaps.openOffline(pcapFile.getAbsolutePath())) {
            long packetNumber = 0;
            Packet packet;

            while ((packet = handle.getNextPacket()) != null) {
                packetNumber++;

                // Get timestamp
                PcapHandle.TimestampPrecision precision = handle.getTimestampPrecision();
                long timestampSec = handle.getTimestamp().getTime() / 1000;
                LocalDateTime timestamp = LocalDateTime.ofInstant(
                        Instant.ofEpochSecond(timestampSec),
                        ZoneId.systemDefault()
                );

                if (result.getStartTime() == null || timestamp.isBefore(result.getStartTime())) {
                    result.setStartTime(timestamp);
                }
                if (result.getEndTime() == null || timestamp.isAfter(result.getEndTime())) {
                    result.setEndTime(timestamp);
                }

                int packetSize = packet.length();
                result.setTotalBytes(result.getTotalBytes() + packetSize);

                // Extract IP layer
                IpPacket ipPacket = packet.get(IpPacket.class);
                if (ipPacket != null) {
                    processIpPacket(ipPacket, packetSize, timestamp, conversationMap, result);
                }
            }

            result.setPacketCount(packetNumber);
            result.setConversations(new ArrayList<>(conversationMap.values()));

            log.info("PCAP analysis completed: {} packets, {} bytes, {} conversations",
                    result.getPacketCount(), result.getTotalBytes(), result.getConversations().size());

        } catch (PcapNativeException | NotOpenException e) {
            log.error("Error analyzing PCAP file: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to analyze PCAP file", e);
        }

        return result;
    }

    private void processIpPacket(IpPacket ipPacket, int packetSize, LocalDateTime timestamp,
                                  Map<String, ConversationInfo> conversationMap,
                                  PcapAnalysisResult result) {
        String srcIp = ipPacket.getHeader().getSrcAddr().getHostAddress();
        String dstIp = ipPacket.getHeader().getDstAddr().getHostAddress();
        String protocol;
        Integer srcPort = null;
        Integer dstPort = null;

        // Check for TCP
        TcpPacket tcpPacket = ipPacket.get(TcpPacket.class);
        if (tcpPacket != null) {
            protocol = "TCP";
            srcPort = tcpPacket.getHeader().getSrcPort().valueAsInt();
            dstPort = tcpPacket.getHeader().getDstPort().valueAsInt();
            incrementProtocolCount(result, protocol, packetSize);
        }
        // Check for UDP
        else if (ipPacket.get(UdpPacket.class) != null) {
            UdpPacket udpPacket = ipPacket.get(UdpPacket.class);
            protocol = "UDP";
            srcPort = udpPacket.getHeader().getSrcPort().valueAsInt();
            dstPort = udpPacket.getHeader().getDstPort().valueAsInt();
            incrementProtocolCount(result, protocol, packetSize);
        }
        // Check for ICMP
        else if (ipPacket.get(IcmpV4CommonPacket.class) != null) {
            protocol = "ICMP";
            incrementProtocolCount(result, protocol, packetSize);
        }
        // Other IP protocols
        else {
            IpNumber ipNumber = ipPacket.getHeader().getProtocol();
            protocol = ipNumber.name();
            incrementProtocolCount(result, protocol, packetSize);
        }

        // Track conversation
        String convKey = createConversationKey(srcIp, srcPort, dstIp, dstPort, protocol);
        final String finalSrcIp = srcIp;
        final String finalDstIp = dstIp;
        final Integer finalSrcPort = srcPort;
        final Integer finalDstPort = dstPort;
        final String finalProtocol = protocol;
        final LocalDateTime finalTimestamp = timestamp;

        ConversationInfo conv = conversationMap.computeIfAbsent(convKey, k -> {
            ConversationInfo newConv = new ConversationInfo();
            newConv.setSrcIp(finalSrcIp);
            newConv.setSrcPort(finalSrcPort);
            newConv.setDstIp(finalDstIp);
            newConv.setDstPort(finalDstPort);
            newConv.setProtocol(finalProtocol);
            newConv.setStartTime(finalTimestamp);
            newConv.setEndTime(finalTimestamp);
            newConv.setPacketCount(0L);
            newConv.setTotalBytes(0L);
            return newConv;
        });

        conv.setPacketCount(conv.getPacketCount() + 1);
        conv.setTotalBytes(conv.getTotalBytes() + packetSize);
        if (timestamp.isAfter(conv.getEndTime())) {
            conv.setEndTime(timestamp);
        }
    }

    private void incrementProtocolCount(PcapAnalysisResult result, String protocol, int packetSize) {
        result.getProtocolCounts().merge(protocol, 1L, Long::sum);
        result.getProtocolBytes().merge(protocol, (long) packetSize, Long::sum);
    }

    private String createConversationKey(String srcIp, Integer srcPort, String dstIp, Integer dstPort, String protocol) {
        // Normalize conversation key (bidirectional)
        String ip1, ip2;
        Integer port1, port2;

        int comparison = srcIp.compareTo(dstIp);
        if (comparison < 0 || (comparison == 0 && (srcPort != null && dstPort != null && srcPort < dstPort))) {
            ip1 = srcIp;
            port1 = srcPort;
            ip2 = dstIp;
            port2 = dstPort;
        } else {
            ip1 = dstIp;
            port1 = dstPort;
            ip2 = srcIp;
            port2 = srcPort;
        }

        return String.format("%s:%s-%s:%s-%s", ip1, port1, ip2, port2, protocol);
    }

    // Result classes
    @lombok.Data
    public static class PcapAnalysisResult {
        private Long packetCount = 0L;
        private Long totalBytes = 0L;
        private LocalDateTime startTime;
        private LocalDateTime endTime;
        private Map<String, Long> protocolCounts;
        private Map<String, Long> protocolBytes;
        private List<ConversationInfo> conversations;
    }

    @lombok.Data
    public static class ConversationInfo {
        private String srcIp;
        private Integer srcPort;
        private String dstIp;
        private Integer dstPort;
        private String protocol;
        private Long packetCount;
        private Long totalBytes;
        private LocalDateTime startTime;
        private LocalDateTime endTime;
    }
}
