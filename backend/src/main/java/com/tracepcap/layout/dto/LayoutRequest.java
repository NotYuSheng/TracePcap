package com.tracepcap.layout.dto;

import java.util.List;
import lombok.Data;

@Data
public class LayoutRequest {

  private String layoutType;
  private List<LayoutNode> nodes;
  private List<LayoutEdge> edges;

  @Data
  public static class LayoutNode {
    private String id;
    private double width;
    private double height;
  }

  @Data
  public static class LayoutEdge {
    private String id;
    private String source;
    private String target;
  }
}
