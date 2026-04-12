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
public class FanOutDetector {

  private final ConversationRepository conversationRepository;

  public List<Finding> detect(UUID fileId) {
    List<Object[]> rows = conversationRepository.findFanOutCandidatesByFileId(fileId);
    List<Finding> findings = new ArrayList<>();

    for (Object[] row : rows) {
      String srcIp = String.valueOf(row[0]);
      long distinctDsts = ((Number) row[1]).longValue();
      long totalFlows = ((Number) row[2]).longValue();

      Severity severity = distinctDsts > 50 ? Severity.HIGH : Severity.MEDIUM;
      Map<String, Object> metrics = new LinkedHashMap<>();
      metrics.put("distinctDstIps", distinctDsts);
      metrics.put("totalFlows", totalFlows);

      findings.add(
          Finding.builder()
              .type(FindingType.FAN_OUT)
              .severity(severity)
              .title(String.format("Fan-Out: %s → %d distinct destinations", srcIp, distinctDsts))
              .summary(
                  String.format(
                      "%s initiated %d flows to %d distinct destination IPs — pattern consistent with scanning or lateral movement.",
                      srcIp, totalFlows, distinctDsts))
              .metrics(metrics)
              .affectedIps(List.of(srcIp))
              .build());
    }
    return findings;
  }
}
