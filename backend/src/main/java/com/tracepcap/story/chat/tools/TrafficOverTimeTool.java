package com.tracepcap.story.chat.tools;

import com.fasterxml.jackson.databind.JsonNode;
import com.tracepcap.analysis.spi.ConversationLookup;
import com.tracepcap.analysis.spi.ConversationLookup.ConversationFacts;
import com.tracepcap.story.chat.ChatTool;
import com.tracepcap.story.service.LlmToolSpec;
import com.tracepcap.timeline.service.TimelineService;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
class TrafficOverTimeTool implements ChatTool {

  private static final int BUCKETS = 24;

  private final TimelineService timeline;
  private final ConversationLookup conversations;

  public String name() { return "traffic_over_time"; }
  public String label() { return "Traffic over time"; }
  public String summary() { return "for the capture or one host"; }
  public String example() { return "When was 192.168.110.9 busiest?"; }

  public LlmToolSpec spec() {
    return new LlmToolSpec(name(),
        "Packets and bytes over the capture in about " + BUCKETS + " time buckets, for the whole capture"
            + " or one host. Use it for when something started, peaked or stopped.",
        LlmToolSpec.schema().property("ip", "string", "Optional: only this host's traffic.").build());
  }

  public Result run(ChatToolContext ctx, JsonNode args) {
    String ip = ToolArgs.text(args, "ip");
    if (ip == null) {
      var points = timeline.getTimelineData(ctx.fileId(), 60, BUCKETS);
      List<Map<String, Object>> rows = points.stream().map(p -> {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("at", p.getTimestamp());
        m.put("packets", p.getPacketCount());
        m.put("bytes", p.getBytes());
        return m;
      }).toList();
      return Result.of(rows.size() + " buckets, whole capture", Map.of("scope", "capture", "buckets", rows));
    }
    List<ConversationFacts> convs = conversations.conversationFactsForIp(ctx.fileId(), ip);
    if (convs.isEmpty()) return Result.of("no traffic for " + ip, Map.of("ip", ip, "buckets", List.of()));
    LocalDateTime start = convs.stream().map(c -> c.flow().startTime()).filter(t -> t != null).min(LocalDateTime::compareTo).orElse(null);
    LocalDateTime end = convs.stream().map(c -> c.flow().endTime() != null ? c.flow().endTime() : c.flow().startTime())
        .filter(t -> t != null).max(LocalDateTime::compareTo).orElse(start);
    if (start == null) return Result.of("no timestamps for " + ip, Map.of("ip", ip, "buckets", List.of()));
    long span = Math.max(1, Duration.between(start, end).toMillis());
    long step = Math.max(1000, span / BUCKETS + 1);
    TreeMap<Long, long[]> buckets = new TreeMap<>();
    for (ConversationFacts c : convs) {
      if (c.flow().startTime() == null) continue;
      long i = Duration.between(start, c.flow().startTime()).toMillis() / step;
      long[] b = buckets.computeIfAbsent(i, k -> new long[3]);
      b[0] += c.flow().packetCount();
      b[1] += c.flow().totalBytes();
      b[2]++;
    }
    List<Map<String, Object>> rows = buckets.entrySet().stream().map(e -> {
      Map<String, Object> m = new LinkedHashMap<>();
      m.put("from", start.plusNanos(e.getKey() * step * 1_000_000));
      m.put("conversationsStarted", e.getValue()[2]);
      m.put("packets", e.getValue()[0]);
      m.put("bytes", e.getValue()[1]);
      return m;
    }).toList();
    return Result.of(convs.size() + " conversations from " + start.toLocalTime() + " to " + end.toLocalTime(),
        Map.of("ip", ip, "first", start, "last", end, "bucketMillis", step, "buckets", rows));
  }
}
