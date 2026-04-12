package com.tracepcap.story.dto;

import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class InvestigationStep {
  private InvestigationQuery query;
  private Hypothesis hypothesis;
  private List<ConversationEvidence> conversations;
  private long conversationCount;
}
