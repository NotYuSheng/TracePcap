package com.lanturn.intelligence.dto;

import java.util.List;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ClusterGraphResponse {
  private String groupType;
  private List<ClusterNodeDto> clusters;
  private List<ClusterEdgeDto> edges;
  private int hiddenClusters;
}
