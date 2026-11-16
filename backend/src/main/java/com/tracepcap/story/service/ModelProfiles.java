package com.tracepcap.story.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Locale;
import java.util.Optional;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.web.client.RestTemplate;

/**
 * What kind of model a name is: one that can chat, or one that can't (an embedding model), and
 * whether it takes tools. OpenAI-compatible servers don't say in /v1/models; LM Studio does, in
 * /api/v0/models (type llm / vlm / embeddings, capabilities [tool_use]), so that is asked first and
 * the model's name is the fallback. Best-effort: anything it can't tell is UNKNOWN, never a failure.
 */
public final class ModelProfiles {

  public enum Kind {
    CHAT,
    VISION,
    EMBEDDING,
    UNKNOWN
  }

  /**
   * @param kind what it can do
   * @param toolUse whether the server says it takes tools; null when the server doesn't say
   * @param contextLength its context window, when the server says
   * @param fromServer whether the server described it, rather than its name being guessed from
   */
  public record Profile(Kind kind, Boolean toolUse, Integer contextLength, boolean fromServer) {
    public boolean canChat() {
      return kind != Kind.EMBEDDING;
    }
  }

  private ModelProfiles() {}

  /** Describes {@code model} on the server at {@code baseUrl} (the API's /v1 base). */
  public static Profile describe(RestTemplate http, ObjectMapper json, String baseUrl, String apiKey, String model) {
    return fromLmStudio(http, json, baseUrl, apiKey, model).orElseGet(() -> fromName(model));
  }

  /** LM Studio's own model list, which says each model's type and capabilities. */
  static Optional<Profile> fromLmStudio(RestTemplate http, ObjectMapper json, String baseUrl, String apiKey, String model) {
    if (baseUrl == null || model == null) return Optional.empty();
    String root = baseUrl.replaceAll("/+$", "").replaceAll("/v1$", "");
    try {
      HttpHeaders h = new HttpHeaders();
      if (apiKey != null && !apiKey.isBlank()) h.setBearerAuth(apiKey);
      String body = http.exchange(root + "/api/v0/models", HttpMethod.GET, new HttpEntity<>(h), String.class).getBody();
      if (body == null) return Optional.empty();
      for (JsonNode m : json.readTree(body).path("data")) {
        if (!model.equals(m.path("id").asText())) continue;
        String type = m.path("type").asText("").toLowerCase(Locale.ROOT);
        Kind kind = switch (type) {
          case "embeddings", "embedding" -> Kind.EMBEDDING;
          case "vlm" -> Kind.VISION;
          case "llm" -> Kind.CHAT;
          default -> Kind.UNKNOWN;
        };
        Boolean tools = null;
        if (m.has("capabilities")) {
          tools = false;
          for (JsonNode c : m.path("capabilities")) if ("tool_use".equals(c.asText())) tools = true;
        } else if (kind == Kind.CHAT || kind == Kind.VISION) {
          tools = false;
        }
        Integer ctx = m.hasNonNull("max_context_length") ? m.get("max_context_length").asInt() : null;
        return Optional.of(new Profile(kind, tools, ctx, true));
      }
      return Optional.empty();
    } catch (Exception e) {
      // Not LM Studio, or it didn't answer: fall back to the name.
      return Optional.empty();
    }
  }

  /** From the name alone: embedding models nearly always say so. */
  static Profile fromName(String model) {
    String n = model == null ? "" : model.toLowerCase(Locale.ROOT);
    boolean embedding = n.contains("embed") || n.contains("bge-") || n.startsWith("e5-") || n.contains("/e5-")
        || n.contains("minilm") || n.contains("rerank");
    return new Profile(embedding ? Kind.EMBEDDING : Kind.UNKNOWN, null, null, false);
  }

  /**
   * Whether the model that answered is the one asked for. Servers report it in their own form
   * ("qwen/qwen3-4b" for "qwen3-4b", or a file name), so a match on the last path segment, or
   * either containing the other, counts.
   */
  public static boolean sameModel(String asked, String answered) {
    if (asked == null || answered == null || asked.isBlank() || answered.isBlank()) return true;
    String a = tail(asked);
    String b = tail(answered);
    return a.equals(b) || a.contains(b) || b.contains(a);
  }

  private static String tail(String s) {
    String t = s.trim().toLowerCase(Locale.ROOT);
    int slash = t.lastIndexOf('/');
    t = slash >= 0 ? t.substring(slash + 1) : t;
    return t.replaceAll("\\.gguf$", "");
  }
}
