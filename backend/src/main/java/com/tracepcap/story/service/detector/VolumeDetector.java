package com.tracepcap.story.service.detector;

import com.tracepcap.analysis.repository.ConversationRepository;
import com.tracepcap.story.dto.Finding;
import com.tracepcap.story.dto.FindingType;
import com.tracepcap.story.dto.Severity;
import java.util.*;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class VolumeDetector {

  private static final long EXFIL_BYTES_THRESHOLD = 10 * 1024 * 1024; // 10 MB
  private static final double ASYMMETRY_RATIO_THRESHOLD = 10.0;

  private final ConversationRepository conversationRepository;

  public List<Finding> detect(UUID fileId, long totalBytes) {
    List<Object[]> rows = conversationRepository.findTopSendersByFileId(fileId);
    List<Finding> findings = new ArrayList<>();

    for (Object[] row : rows) {
      String srcIp = String.valueOf(row[0]);
      long senderBytes = ((Number) row[1]).longValue();
      long flowCount = ((Number) row[2]).longValue();

      if (totalBytes <= 0) continue;
      double pct = (senderBytes * 100.0) / totalBytes;

      // Flag top talker if it accounts for >40% of total traffic
      if (pct > 40.0) {
        Map<String, Object> metrics = new LinkedHashMap<>();
        metrics.put("bytes", senderBytes);
        metrics.put("pctOfTotal", Math.round(pct * 10.0) / 10.0);
        metrics.put("flowCount", flowCount);
        findings.add(
            Finding.builder()
                .type(FindingType.VOLUME)
                .severity(Severity.MEDIUM)
                .title(String.format("Top Talker: %s (%.1f%% of traffic)", srcIp, pct))
                .summary(
                    String.format(
                        "%s generated %d bytes across %d flows, accounting for %.1f%% of total capture traffic.",
                        srcIp, senderBytes, flowCount, pct))
                .metrics(metrics)
                .affectedIps(List.of(srcIp))
                .build());
      }

      // Flag potential exfiltration: large outbound volume from single internal host
      if (senderBytes >= EXFIL_BYTES_THRESHOLD) {
        Map<String, Object> metrics = new LinkedHashMap<>();
        metrics.put("outboundBytes", senderBytes);
        metrics.put("flowCount", flowCount);
        Severity severity = senderBytes > 100 * 1024 * 1024 ? Severity.HIGH : Severity.MEDIUM;
        findings.add(
            Finding.builder()
                .type(FindingType.VOLUME)
                .severity(severity)
                .title(
                    String.format("High Outbound Volume: %s sent %s", srcIp, fmtBytes(senderBytes)))
                .summary(
                    String.format(
                        "%s sent %d bytes (%s) across %d outbound flows — warrants review for data exfiltration.",
                        srcIp, senderBytes, fmtBytes(senderBytes), flowCount))
                .metrics(metrics)
                .affectedIps(List.of(srcIp))
                .build());
      }
    }

    // Deduplicate: if same src_ip produced both findings, keep only the higher-severity one
    Map<String, Finding> bestBySrc = new LinkedHashMap<>();
    for (Finding f : findings) {
      if (f.getAffectedIps().isEmpty()) continue;
      String ip = f.getAffectedIps().get(0);
      Finding existing = bestBySrc.get(ip);
      if (existing == null || f.getSeverity().ordinal() < existing.getSeverity().ordinal()) {
        bestBySrc.put(ip, f);
      }
    }
    return new ArrayList<>(bestBySrc.values());
  }

  private static String fmtBytes(long bytes) {
    if (bytes >= 1_073_741_824L) return String.format("%.1f GB", bytes / 1_073_741_824.0);
    if (bytes >= 1_048_576L) return String.format("%.1f MB", bytes / 1_048_576.0);
    if (bytes >= 1_024L) return String.format("%.1f KB", bytes / 1_024.0);
    return bytes + " B";
  }
}
