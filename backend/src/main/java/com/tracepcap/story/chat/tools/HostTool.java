package com.tracepcap.story.chat.tools;

import com.fasterxml.jackson.databind.JsonNode;
import com.tracepcap.analysis.spi.CaptureNetworkLookup;
import com.tracepcap.analysis.spi.ConversationLookup;
import com.tracepcap.analysis.spi.ConversationLookup.ConversationFacts;
import com.tracepcap.analysis.spi.HostClassificationLookup;
import com.tracepcap.story.chat.ChatTool;
import com.tracepcap.story.service.LlmToolSpec;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
class HostTool implements ChatTool {

  private final HostClassificationLookup hosts;
  private final ConversationLookup conversations;
  private final CaptureNetworkLookup networks;

  public String name() { return "get_host"; }
  public String label() { return "Host"; }
  public String summary() { return "name, device, MAC, roles, its traffic"; }
  public String example() { return "What is 192.168.110.9?"; }

  public LlmToolSpec spec() {
    return new LlmToolSpec(name(),
        "One host by IP address: its name, device type and confidence, MAC and vendor, service roles,"
            + " which network it is on, whether other devices held the address, and a summary of its"
            + " traffic (conversations, bytes, top peers and apps).",
        LlmToolSpec.schema().property("ip", "string", "The host's IP address.").require("ip").build());
  }

  public Result run(ChatToolContext ctx, JsonNode args) {
    String ip = ToolArgs.text(args, "ip");
    if (ip == null) throw new IllegalArgumentException("Give the host's ip.");
    var facts = hosts.hostFacts(ctx.fileId()).stream().filter(h -> ip.equals(h.ip())).findFirst().orElse(null);
    List<ConversationFacts> convs = conversations.conversationFactsForIp(ctx.fileId(), ip);
    if (facts == null && convs.isEmpty()) {
      return Result.of("not in this capture", Map.of("ip", ip, "found", false));
    }
    Map<String, Object> m = new LinkedHashMap<>();
    m.put("ip", ip);
    if (facts != null) {
      m.put("hostname", facts.hostname());
      m.put("hostnameSource", facts.hostnameSource());
      m.put("deviceType", facts.deviceType());
      m.put("confidence", facts.confidence());
      m.put("mac", facts.mac());
      m.put("vendor", facts.manufacturer());
      m.put("serviceRoles", facts.serviceRoles());
      if (facts.loggedInUser() != null) m.put("signedInUser", facts.loggedInUser());
    }
    var segs = networks.networks(ctx.fileId());
    if (segs != null) {
      segs.segments().stream()
          .filter(s -> s.clients().stream().anyMatch(c -> ip.equals(c.ip())) || (s.routers() != null && s.routers().contains(ip)))
          .findFirst()
          .ifPresent(s -> m.put("network", s.label() + (s.routers() != null && s.routers().contains(ip) ? " (its gateway)" : "")));
    }
    networks.sharedAddresses(ctx.fileId()).stream().filter(r -> ip.equals(r.ip())).findFirst()
        .ifPresent(r -> m.put("heldBy", r.occupancies().stream()
            .map(o -> Map.of("mac", String.valueOf(o.getMac()), "hostname", String.valueOf(o.getHostname()),
                "from", String.valueOf(o.getStartsAt()), "until", String.valueOf(o.getEndsAt())))
            .toList()));
    long bytes = convs.stream().mapToLong(c -> c.flow().totalBytes()).sum();
    Map<String, Long> peers = convs.stream().collect(Collectors.groupingBy(
        c -> ip.equals(c.flow().srcIp()) ? c.flow().dstIp() : c.flow().srcIp(), Collectors.summingLong(c -> c.flow().totalBytes())));
    Map<String, Long> apps = convs.stream().collect(Collectors.groupingBy(
        c -> c.findings() != null && c.findings().appName() != null ? c.findings().appName() : String.valueOf(c.flow().protocol()),
        Collectors.counting()));
    m.put("conversations", convs.size());
    m.put("bytes", bytes);
    m.put("topPeersByBytes", top(peers, 8));
    m.put("appsByConversations", top(apps, 8));
    String name = facts != null && facts.hostname() != null ? facts.hostname() + ", " : "";
    String type = facts != null && facts.deviceType() != null ? facts.deviceType().toLowerCase().replace('_', ' ') + ", " : "";
    return Result.of(name + type + convs.size() + " conversations", m);
  }

  private static Map<String, Long> top(Map<String, Long> m, int n) {
    Map<String, Long> out = new LinkedHashMap<>();
    m.entrySet().stream().sorted(Map.Entry.<String, Long>comparingByValue(Comparator.reverseOrder())).limit(n)
        .forEach(e -> out.put(e.getKey(), e.getValue()));
    return out;
  }
}
