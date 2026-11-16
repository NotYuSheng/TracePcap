package com.tracepcap.filter.chat;

import com.fasterxml.jackson.databind.JsonNode;
import com.tracepcap.filter.service.FilterService;
import com.tracepcap.story.chat.ChatTool;
import com.tracepcap.story.service.LlmToolSpec;
import java.util.LinkedHashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * The Filter Generator, as a capture-chat tool (#1161): the model writes the filter, this checks it
 * on the capture. It lives in the filter module (which already depends on story) so story never
 * depends back on filter; the chat's registry finds it as a bean.
 */
@Component
@RequiredArgsConstructor
class CheckFilterTool implements ChatTool {

  private final FilterService filters;

  public String name() { return "check_filter"; }
  public String label() { return "Check a filter"; }
  public String summary() { return "Wireshark display filter: valid, and what matches"; }
  public String example() { return "A filter for the beacon traffic"; }

  public LlmToolSpec spec() {
    return new LlmToolSpec(name(),
        "Check a Wireshark display filter against this capture: whether it is valid, and how many"
            + " packets match. Call it whenever you suggest a filter, and only suggest filters it found"
            + " valid; fix and re-check one it rejects.",
        LlmToolSpec.schema()
            .property("filter", "string", "The display filter, e.g. ip.addr == 10.0.0.5 && udp.port == 53.")
            .require("filter").build());
  }

  public Result run(ChatToolContext ctx, JsonNode args) {
    String expr = args == null || args.path("filter").isMissingNode() ? null : args.path("filter").asText("").trim();
    if (expr == null || expr.isEmpty()) throw new IllegalArgumentException("Give the filter.");
    try {
      var r = filters.executeFilter(ctx.fileId(), expr, 1, 3);
      int matches = r.getTotalMatches() == null ? 0 : r.getTotalMatches();
      Map<String, Object> data = new LinkedHashMap<>();
      data.put("filter", expr);
      data.put("valid", true);
      data.put("matchingPackets", matches);
      return new Result("valid · " + matches + (matches == 1 ? " packet matches" : " packets match"), data,
          new CheckedFilter(expr, true, matches, null));
    } catch (RuntimeException e) {
      String why = e.getMessage() == null ? "rejected" : e.getMessage();
      if (why.length() > 300) why = why.substring(0, 300);
      return new Result("rejected: " + why, Map.of("filter", expr, "valid", false, "error", why),
          new CheckedFilter(expr, false, null, why));
    }
  }
}
