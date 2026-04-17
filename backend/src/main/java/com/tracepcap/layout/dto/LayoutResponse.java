package com.tracepcap.layout.dto;

import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class LayoutResponse {

  private List<NodePosition> positions;

  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  public static class NodePosition {
    private String id;
    private double x;
    private double y;
  }
}
