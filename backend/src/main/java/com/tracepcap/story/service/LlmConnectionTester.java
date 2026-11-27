package com.tracepcap.story.service;

import com.tracepcap.common.text.Humanize;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracepcap.common.exception.ForbiddenException;
import com.tracepcap.common.settings.EditablePolicy;
import com.tracepcap.common.settings.LlmSettings;
import com.tracepcap.common.settings.PolicyEditGate;
import com.tracepcap.story.dto.LlmTestRequest;
import com.tracepcap.story.dto.LlmTestResult;
import com.tracepcap.story.dto.LlmTestResult.Step;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;

/**
 * Tests an LLM connection step by step, so a failure says which part is wrong: the server can't
 * be reached, the key is refused, the model isn't there, or it doesn't answer. Tests the current
 * settings, which anyone may, or values that haven't been saved yet, which only those allowed to
 * change the LLM connection may: those requests go wherever the values say.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class LlmConnectionTester {

  /** Listing models is quick; a server that takes longer is effectively unreachable. */
  static final int LIST_TIMEOUT_MS = 10_000;
  /** A one-token reply, capped well below a story's timeout so the test can't hang the page. */
  static final int REPLY_TIMEOUT_CAP_MS = 120_000;
  /** Enough for a reasoning model to show that it reasons, still a quick reply. */
  static final int REPLY_TOKENS = 24;
  /** Asks for more than {@link #REPLY_TOKENS}, so every model writes the whole reply and its speed shows. */
  static final String SPEED_PROMPT = "Count from 1 to 40, separated by spaces.";
  /** A reply shorter than this says too little about speed (an "OK", a cold load): no estimate. */
  static final int MIN_SPEED_TOKENS = REPLY_TOKENS / 2;

  /** A Story on a busy capture sends 10,000–20,000 tokens; under this it may be refused. */
  static final int STORY_MIN_CONTEXT = 16_384;
  /** A reasoning model thinks before the story too, so it wants twice that. */
  static final int REASONING_MIN_CONTEXT = 32_768;
  /** About how long a story's reply is, in tokens; a reasoning model's thinking triples it. */
  static final int STORY_REPLY_TOKENS = 4_000;
  /** Under this cap a story's reply is cut off; a reasoning model needs the higher one. */
  static final int STORY_MIN_CAP = 4_000;
  static final int REASONING_MIN_CAP = 24_000;

  private final LlmSettings settings;
  private final PolicyEditGate editGate;
  private final ObjectMapper objectMapper;
  private final com.tracepcap.config.LlmConfig llmConfig;

  public LlmTestResult test(LlmTestRequest request) {
    // Testing what's in effect points nowhere new, so anyone may. Testing other values sends
    // requests wherever they say (and a key along), so that takes the permission to change them.
    boolean candidate =
        request != null
            && (!blank(request.getBaseUrl()) || !blank(request.getApiKey()) || !blank(request.getModel()));
    if (candidate && !editGate.canEdit(EditablePolicy.Kind.LLM)) {
      throw new ForbiddenException(editGate.reason(EditablePolicy.Kind.LLM));
    }
    String baseUrl = blank(request == null ? null : request.getBaseUrl())
        ? settings.baseUrl()
        : EditablePolicy.LLM_API_BASE_URL.normalise(request.getBaseUrl());
    String apiKey = blank(request == null ? null : request.getApiKey()) ? settings.apiKey() : request.getApiKey().trim();
    String model = blank(request == null ? null : request.getModel()) ? settings.model() : request.getModel().trim();

    List<Step> steps = new ArrayList<>();
    List<String> models = new ArrayList<>();

    // 1. Reach the server and 2. have the key accepted: GET /models.
    long t0 = System.currentTimeMillis();
    JsonNode listed = null;
    Integer status = null;
    String failure = null;
    try {
      String body = template(LIST_TIMEOUT_MS)
          .exchange(baseUrl + "/models", HttpMethod.GET, new HttpEntity<>(headers(apiKey)), String.class)
          .getBody();
      listed = body == null ? null : objectMapper.readTree(body);
      status = 200;
    } catch (HttpStatusCodeException e) {
      status = e.getStatusCode().value();
      failure = e.getStatusText();
    } catch (Exception e) {
      failure = rootMessage(e);
    }
    long listMs = System.currentTimeMillis() - t0;

    if (status == null) {
      steps.add(fail("reach", "Reach the server", "Couldn't reach " + baseUrl + ": " + failure, listMs));
      steps.add(skip("key", "Key accepted"));
      steps.add(skip("model", "Model available"));
      steps.add(skip("reply", "Model replies"));
      return result(steps, models, baseUrl, model);
    }
    steps.add(ok("reach", "Reach the server", "Answered in " + listMs + " ms.", listMs));

    if (status == 401 || status == 403) {
      steps.add(fail("key", "Key accepted", "The server refused the key (" + status + ").", listMs));
      steps.add(skip("model", "Model available"));
      steps.add(skip("reply", "Model replies"));
      return result(steps, models, baseUrl, model);
    }
    if (status != 200) {
      steps.add(fail("key", "Key accepted",
          "The server answered " + status + " " + (failure == null ? "" : failure).trim()
              + " for /models. Is " + baseUrl + " the API's base URL (it usually ends in /v1)?",
          listMs));
      steps.add(skip("model", "Model available"));
      steps.add(skip("reply", "Model replies"));
      return result(steps, models, baseUrl, model);
    }
    steps.add(ok("key", "Key accepted", "The server accepted the request.", listMs));

    // 3. The model is among the server's.
    JsonNode entry = null;
    if (listed != null && listed.path("data").isArray()) {
      for (JsonNode m : listed.path("data")) {
        if (m.hasNonNull("id")) models.add(m.get("id").asText());
        if (model.equals(m.path("id").asText(null))) entry = m;
      }
    }
    ModelProfiles.Profile profile = ModelProfiles.describe(template(LIST_TIMEOUT_MS), objectMapper, baseUrl, apiKey, model);
    if (!profile.canChat() && (models.isEmpty() || models.contains(model))) {
      // An embedding model turns text into vectors for search; it can't write an answer.
      steps.add(fail("model", "Model available",
          model + " is an embedding model: it turns text into numbers for search and can't write answers."
              + " Pick a chat model.", null));
      steps.add(skip("reply", "Model replies"));
      return result(steps, models, baseUrl, model);
    }
    String kindNote = profile.kind() == ModelProfiles.Kind.VISION ? " It's a vision model, which chats too." : "";
    if (models.isEmpty()) {
      steps.add(Step.builder().key("model").label("Model available").status("OK")
          .detail("The server doesn't list its models, so " + model + " is tried directly below.").build());
    } else if (models.contains(model)) {
      steps.add(ok("model", "Model available", model + " is one of the server's " + models.size() + " models." + kindNote, null));
    } else {
      steps.add(fail("model", "Model available",
          model + " isn't among the server's " + models.size() + " models. Pick one of them.", null));
      steps.add(skip("reply", "Model replies"));
      return result(steps, models, baseUrl, model);
    }

    // 4. A one-token reply.
    long t1 = System.currentTimeMillis();
    String reply = null;
    long replyMs = 0;
    try {
      Map<String, Object> body = Map.of(
          "model", model,
          "messages", List.of(Map.of("role", "user", "content", SPEED_PROMPT)),
          "max_tokens", REPLY_TOKENS,
          "temperature", 0);
      HttpHeaders h = headers(apiKey);
      h.setContentType(MediaType.APPLICATION_JSON);
      reply = template(Math.min(settings.timeoutSeconds() * 1000, REPLY_TIMEOUT_CAP_MS))
          .exchange(baseUrl + "/chat/completions", HttpMethod.POST, new HttpEntity<>(body, h), String.class)
          .getBody();
      replyMs = System.currentTimeMillis() - t1;
      steps.add(replyStep(model, reply, replyMs));
    } catch (HttpStatusCodeException e) {
      steps.add(fail("reply", "Model replies",
          "The server answered " + e.getStatusCode().value() + ": " + shorten(e.getResponseBodyAsString()),
          System.currentTimeMillis() - t1));
    } catch (Exception e) {
      steps.add(fail("reply", "Model replies", "No reply: " + rootMessage(e), System.currentTimeMillis() - t1));
    }
    if (profile.toolUse() != null) {
      steps.add(profile.toolUse()
          ? ok("tools", "Takes tools", "The server says it takes tools, so the chat can look things up.", null)
          : warn("tools", "Takes tools",
              "The server says it doesn't take tools, so the chat will answer from the findings and the story only.", null));
    }
    // 5. Whether it can carry a story: its context, the cap, its speed. Warnings only.
    if (reply != null) {
      // A configured LLM_CONTEXT_LENGTH is what replies are sized to, so it's what counts here.
      Integer context = llmConfig.getApi() == null ? null : llmConfig.getApi().getContextLength();
      if (context == null) context = LlmClient.contextLengthOf(entry);
      if (context == null && entry != null && LlmClient.namesItsLimit(entry.path("owned_by").asText(null))) {
        context = LlmClient.probe(template(LIST_TIMEOUT_MS), baseUrl, apiKey, model).contextLength();
      }
      ReplyFacts facts = replyFacts(reply);
      steps.add(capacityStep(context, facts.reasoning(), facts.completionTokens(), replyMs,
          settings.maxTokens(), settings.timeoutSeconds()));
    }
    return result(steps, models, baseUrl, model);
  }

  /** A model the server offers, with its context length when the server says. */
  public record ModelOption(String id, Integer contextLength) {}

  /** The server's models, or why they couldn't be listed. */
  public record ModelList(boolean ok, String baseUrl, List<ModelOption> models, String detail) {}

  /**
   * The server's models, for picking one before saving. Blank fields use the current settings;
   * other values take the permission to change the LLM connection, as with {@link #test}.
   */
  public ModelList listModels(LlmTestRequest request) {
    boolean candidate =
        request != null && (!blank(request.getBaseUrl()) || !blank(request.getApiKey()));
    if (candidate && !editGate.canEdit(EditablePolicy.Kind.LLM)) {
      throw new ForbiddenException(editGate.reason(EditablePolicy.Kind.LLM));
    }
    String baseUrl = blank(request == null ? null : request.getBaseUrl())
        ? settings.baseUrl()
        : EditablePolicy.LLM_API_BASE_URL.normalise(request.getBaseUrl());
    String apiKey = blank(request == null ? null : request.getApiKey()) ? settings.apiKey() : request.getApiKey().trim();
    try {
      String body = template(LIST_TIMEOUT_MS)
          .exchange(baseUrl + "/models", HttpMethod.GET, new HttpEntity<>(headers(apiKey)), String.class)
          .getBody();
      JsonNode listed = body == null ? null : objectMapper.readTree(body);
      List<ModelOption> models = new ArrayList<>();
      if (listed != null && listed.path("data").isArray()) {
        for (JsonNode m : listed.path("data")) {
          if (m.hasNonNull("id")) models.add(new ModelOption(m.get("id").asText(), LlmClient.contextLengthOf(m)));
        }
      }
      return new ModelList(true, baseUrl, models,
          models.isEmpty() ? "The server doesn't list its models: type the model's name." : null);
    } catch (HttpStatusCodeException e) {
      int status = e.getStatusCode().value();
      return new ModelList(false, baseUrl, List.of(), status == 401 || status == 403
          ? "The server refused the key (" + status + ")."
          : "The server answered " + status + " for /models. Is " + baseUrl + " the API's base URL (it usually ends in /v1)?");
    } catch (Exception e) {
      return new ModelList(false, baseUrl, List.of(), "Couldn't reach " + baseUrl + ": " + rootMessage(e));
    }
  }

  /** What the test reply shows about the model. */
  record ReplyFacts(String answered, boolean reasoning, Integer completionTokens) {}

  ReplyFacts replyFacts(String reply) {
    try {
      JsonNode r = reply == null ? null : objectMapper.readTree(reply);
      if (r == null) return new ReplyFacts(null, false, null);
      JsonNode msg = r.path("choices").path(0).path("message");
      String thought = msg.path("reasoning_content").asText(msg.path("reasoning").asText(""));
      boolean reasoning = !thought.isBlank() || msg.path("content").asText("").contains("<think>");
      JsonNode used = r.path("usage").path("completion_tokens");
      return new ReplyFacts(r.path("model").asText(null), reasoning, used.canConvertToInt() ? used.asInt() : null);
    } catch (Exception e) {
      // A reply that isn't JSON still counts as a reply.
      return new ReplyFacts(null, false, null);
    }
  }

  /**
   * Whether this model can carry a story, from what the test saw: a context too small for a
   * story's prompt, a reasoning model with no room to think, a cap that cuts replies off, or a
   * speed that runs past the timeout. Warns, never fails: it may still do for small captures.
   *
   * @param context the context length, null when the server didn't say
   * @param completionTokens the test reply's tokens, null when the server didn't count them
   * @param ceiling LLM_MAX_TOKENS, 0 for none
   */
  static Step capacityStep(
      Integer context, boolean reasoning, Integer completionTokens, long replyMs, int ceiling, int timeoutSeconds) {
    List<String> warnings = new ArrayList<>();
    List<String> notes = new ArrayList<>();
    if (context == null) {
      notes.add("The server doesn't say how large its context is; replies get "
          + (ceiling > 0 ? n(ceiling) + " tokens (LLM_MAX_TOKENS)" : n(LlmClient.FALLBACK_REPLY_TOKENS) + " tokens, then the rest if cut off")
          + ". Set LLM_CONTEXT_LENGTH to size them to it.");
    } else if (reasoning && context < REASONING_MIN_CONTEXT) {
      warnings.add("Its context holds " + n(context) + " tokens. A reasoning model thinks before it writes, so a story"
          + " needs " + n(REASONING_MIN_CONTEXT) + " or more: on a busy capture it may be cut off or refused.");
    } else if (context < STORY_MIN_CONTEXT) {
      warnings.add("Its context holds " + n(context) + " tokens. A story on a busy capture sends 10,000–20,000, so it"
          + " may be refused; " + n(STORY_MIN_CONTEXT) + " or more is comfortable.");
    } else {
      notes.add("Its context holds " + n(context) + " tokens; each reply gets what the prompt leaves.");
    }
    int minCap = reasoning ? REASONING_MIN_CAP : STORY_MIN_CAP;
    if (ceiling > 0 && ceiling < minCap) {
      warnings.add("LLM_MAX_TOKENS caps replies at " + n(ceiling) + "; " + (reasoning ? "a reasoning model's" : "a")
          + " story needs " + n(minCap) + " or more. Set it to 0 to size replies to the context.");
    }
    if (completionTokens != null && completionTokens >= MIN_SPEED_TOKENS && replyMs > 0) {
      // A 24-token reply includes the prompt's processing, so this is a floor on its speed.
      double perSecond = completionTokens * 1000.0 / replyMs;
      int storyTokens = reasoning ? STORY_REPLY_TOKENS * 3 : STORY_REPLY_TOKENS;
      long storySeconds = Math.round(storyTokens / perSecond);
      String speed = "about " + Math.round(perSecond) + " tokens a second";
      if (storySeconds > timeoutSeconds) {
        warnings.add("It writes " + speed + ", so a story (about " + n(storyTokens) + " tokens) may take "
            + Humanize.span(storySeconds * 1000L) + ", past LLM_TIMEOUT of " + timeoutSeconds + " s. Raise LLM_TIMEOUT to "
            + n(storySeconds + 60) + " or more, or use a faster model or server.");
      } else {
        notes.add("It writes " + speed + ": a story takes about " + Humanize.span(storySeconds * 1000L) + ".");
      }
    }
    String detail = String.join(" ", warnings.isEmpty() ? notes : warnings);
    return warnings.isEmpty()
        ? ok("capacity", "Can carry a story", detail, null)
        : warn("capacity", "Can carry a story", detail, null);
  }

  private static String n(long v) {
    return String.format(java.util.Locale.ROOT, "%,d", v);
  }

  /** The reply's own model and form: a different model answering, or a reasoning model. */
  Step replyStep(String asked, String reply, long ms) {
    ReplyFacts facts = replyFacts(reply);
    String answered = facts.answered();
    boolean reasoning = facts.reasoning();
    String think = reasoning
        ? " It's a reasoning model: it thinks before it answers, so leave LLM_MAX_TOKENS at 0 (or 24000 or more) and give it a long LLM_TIMEOUT."
        : "";
    if (!ModelProfiles.sameModel(asked, answered)) {
      return warn("reply", "Model replies",
          "Replied in " + ms + " ms, but as " + answered + ": the server answered with a different model than "
              + asked + ", usually the one it has loaded. Load " + asked + " on the server, or set the model to "
              + answered + "." + think, ms);
    }
    return ok("reply", "Model replies", "Replied in " + ms + " ms." + think, ms);
  }

  private static LlmTestResult result(List<Step> steps, List<String> models, String baseUrl, String model) {
    // A warning (another model answered, no tools) still works; only a failure means it doesn't.
    boolean ok = steps.stream().noneMatch(s -> "FAIL".equals(s.getStatus()) || "SKIPPED".equals(s.getStatus()));
    return LlmTestResult.builder().ok(ok).steps(steps).models(models).baseUrl(baseUrl).model(model).build();
  }

  private static HttpHeaders headers(String apiKey) {
    HttpHeaders h = new HttpHeaders();
    if (!blank(apiKey)) h.setBearerAuth(apiKey);
    return h;
  }

  private static RestTemplate template(int timeoutMs) {
    SimpleClientHttpRequestFactory f = new SimpleClientHttpRequestFactory();
    f.setConnectTimeout(Math.min(timeoutMs, LIST_TIMEOUT_MS));
    f.setReadTimeout(timeoutMs);
    return new RestTemplate(f);
  }

  private static Step ok(String key, String label, String detail, Long ms) {
    return Step.builder().key(key).label(label).status("OK").detail(detail).ms(ms).build();
  }

  private static Step warn(String key, String label, String detail, Long ms) {
    return Step.builder().key(key).label(label).status("WARN").detail(detail).ms(ms).build();
  }

  private static Step fail(String key, String label, String detail, Long ms) {
    return Step.builder().key(key).label(label).status("FAIL").detail(detail).ms(ms).build();
  }

  private static Step skip(String key, String label) {
    return Step.builder().key(key).label(label).status("SKIPPED").detail("Skipped: an earlier step failed.").build();
  }

  private static boolean blank(String s) {
    return s == null || s.isBlank();
  }

  private static String rootMessage(Throwable e) {
    Throwable t = e;
    while (t.getCause() != null && t.getCause() != t) t = t.getCause();
    String m = t.getMessage();
    return m == null ? t.getClass().getSimpleName() : m;
  }

  private static String shorten(String s) {
    if (s == null || s.isBlank()) return "(no detail)";
    String one = s.replaceAll("\\s+", " ").trim();
    return one.length() > 300 ? one.substring(0, 300) + "…" : one;
  }
}
