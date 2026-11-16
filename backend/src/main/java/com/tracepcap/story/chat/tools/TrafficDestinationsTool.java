package com.tracepcap.story.chat.tools;

import com.fasterxml.jackson.databind.JsonNode;
import com.tracepcap.cluster.dto.ClusterNodeDto;
import com.tracepcap.cluster.service.NetworkClusterService;
import com.tracepcap.story.chat.ChatTool;
import com.tracepcap.story.service.LlmToolSpec;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
class TrafficDestinationsTool implements ChatTool {

  private final NetworkClusterService cluster;

  public String name() { return "where_traffic_goes"; }
  public String label() { return "Where traffic goes"; }
  public String summary() { return "organisations and countries"; }
  public String example() { return "What talked to Russia?"; }

  public LlmToolSpec spec() {
    return new LlmToolSpec(name(),
        "Traffic grouped by organisation (from GeoIP and the analyst's network labels) or by country:"
            + " bytes, conversations and hosts per group, the biggest first, with each group's addresses.",
        LlmToolSpec.schema()
            .enumProperty("by", "Group by organisation or by country (default organisation).", List.of("organisation", "country"))
            .property("limit", "integer", "How many groups (default 10, at most 30).")
            .build());
  }

  public Result run(ChatToolContext ctx, JsonNode args) {
    String by = "country".equalsIgnoreCase(ToolArgs.text(args, "by")) ? "country" : "asn";
    var graph = cluster.computeClusters(ctx.fileId(), by, null, List.of(), ctx.networkId());
    List<ClusterNodeDto> groups = graph == null || graph.getClusters() == null ? List.of()
        : graph.getClusters().stream().sorted(Comparator.comparingLong(ClusterNodeDto::getTotalBytes).reversed()).toList();
    int limit = ToolArgs.limit(args, 10, 30);
    List<Map<String, Object>> rows = groups.stream().limit(limit).map(n -> {
      Map<String, Object> m = new LinkedHashMap<>();
      m.put("group", n.getLabel());
      m.put("bytes", n.getTotalBytes());
      m.put("conversations", n.getConversationCount());
      m.put("hosts", n.getHostCount());
      m.put("flagged", n.getRiskCount());
      if (n.getIpBytes() != null) m.put("addresses", n.getIpBytes().keySet().stream().limit(12).toList());
      return m;
    }).toList();
    String top = groups.isEmpty() ? "" : ", biggest " + groups.get(0).getLabel();
    return Result.of(groups.size() + (by.equals("asn") ? " organisations" : " countries") + top,
        Map.of("groupedBy", by.equals("asn") ? "organisation" : "country", "groups", rows));
  }
}
