package com.tracepcap.story.chat.tools;

import com.fasterxml.jackson.databind.JsonNode;
import com.tracepcap.analysis.spi.CaptureNetworkLookup;
import com.tracepcap.story.chat.ChatTool;
import com.tracepcap.story.service.LlmToolSpec;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
class AddressHistoryTool implements ChatTool {

  private final CaptureNetworkLookup networks;

  public String name() { return "who_held_address"; }
  public String label() { return "Who held an address"; }
  public String summary() { return "which device had an IP, and when"; }
  public String example() { return "Which device had 10.20.20.51 at 17:25?"; }

  public LlmToolSpec spec() {
    return new LlmToolSpec(name(),
        "Which device (MAC, hostname) held an IP address over the capture, from ARP and DHCP. Use it"
            + " before blaming a device for traffic from an address that changed hands. Also lists"
            + " devices that moved from one address to another.",
        LlmToolSpec.schema()
            .property("ip", "string", "The IP address.")
            .property("at", "string", "Optional time, ISO-8601 (e.g. 2026-11-14T17:25:00): who held it then.")
            .require("ip").build());
  }

  public Result run(ChatToolContext ctx, JsonNode args) {
    String ip = ToolArgs.text(args, "ip");
    if (ip == null) throw new IllegalArgumentException("Give the ip.");
    LocalDateTime at = null;
    String atText = ToolArgs.text(args, "at");
    if (atText != null) {
      try {
        at = LocalDateTime.parse(atText.replace("Z", "").replace(' ', 'T'));
      } catch (RuntimeException e) {
        throw new IllegalArgumentException("'at' must be ISO-8601, e.g. 2026-11-14T17:25:00.");
      }
    }
    var holders = networks.sharedAddresses(ctx.fileId()).stream().filter(r -> ip.equals(r.ip())).findFirst()
        .map(r -> r.occupancies()).orElse(List.of());
    var moves = networks.moves(ctx.fileId()).stream().filter(m -> ip.equals(m.fromIp()) || ip.equals(m.toIp())).toList();
    Map<String, Object> out = new LinkedHashMap<>();
    out.put("ip", ip);
    out.put("devices", holders.stream().map(o -> {
      Map<String, Object> d = new LinkedHashMap<>();
      d.put("mac", o.getMac());
      d.put("hostname", o.getHostname());
      d.put("from", o.getStartsAt());
      d.put("until", o.getEndsAt());
      d.put("evidence", o.getStartEvidence());
      return d;
    }).toList());
    out.put("moves", moves);
    String summary;
    if (holders.size() < 2) {
      summary = "one device held it throughout";
      out.put("note", "One device held this address for the whole capture.");
    } else {
      summary = holders.size() + " devices in turn";
    }
    if (at != null && holders.size() > 1) {
      final LocalDateTime t = at;
      var h = holders.stream().filter(o -> (o.getStartsAt() == null || !t.isBefore(o.getStartsAt()))
          && (o.getEndsAt() == null || t.isBefore(o.getEndsAt()))).findFirst().orElse(null);
      if (h != null) {
        out.put("heldAt", Map.of("at", t.toString(), "mac", String.valueOf(h.getMac()), "hostname", String.valueOf(h.getHostname())));
        summary += "; at " + t.toLocalTime() + ": " + (h.getHostname() != null ? h.getHostname() : h.getMac());
      }
    }
    return Result.of(summary, out);
  }
}
