package com.tracepcap.story.chat;

import com.tracepcap.story.service.LlmToolSpec;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.stereotype.Component;

/** Every {@link ChatTool} bean, by name, in a stable order. */
@Component
public class ChatToolRegistry {

  private final Map<String, ChatTool> tools = new LinkedHashMap<>();

  public ChatToolRegistry(List<ChatTool> found) {
    found.stream()
        .sorted(Comparator.comparingInt(ChatToolRegistry::order).thenComparing(ChatTool::name))
        .forEach(t -> tools.put(t.name(), t));
  }

  public List<ChatTool> all() {
    return List.copyOf(tools.values());
  }

  public Optional<ChatTool> find(String name) {
    return Optional.ofNullable(tools.get(name));
  }

  public List<LlmToolSpec> specs() {
    return tools.values().stream().map(ChatTool::spec).toList();
  }

  /** The tools list's order: the capture's analysis, then hosts and addresses, then packets. */
  private static int order(ChatTool t) {
    return switch (t.name()) {
      case "get_findings" -> 0;
      case "find_conversations" -> 1;
      case "traffic_over_time" -> 2;
      case "get_host" -> 3;
      case "who_held_address" -> 4;
      case "dns_lookups" -> 5;
      case "where_traffic_goes" -> 6;
      case "check_filter" -> 7;
      default -> 50;
    };
  }
}
