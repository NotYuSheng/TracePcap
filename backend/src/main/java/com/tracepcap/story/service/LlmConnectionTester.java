package com.tracepcap.story.service;

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

  private final LlmSettings settings;
  private final PolicyEditGate editGate;
  private final ObjectMapper objectMapper;

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
    if (listed != null && listed.path("data").isArray()) {
      for (JsonNode m : listed.path("data")) {
        if (m.hasNonNull("id")) models.add(m.get("id").asText());
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
    try {
      Map<String, Object> body = Map.of(
          "model", model,
          "messages", List.of(Map.of("role", "user", "content", "Reply with OK.")),
          "max_tokens", REPLY_TOKENS,
          "temperature", 0);
      HttpHeaders h = headers(apiKey);
      h.setContentType(MediaType.APPLICATION_JSON);
      String reply = template(Math.min(settings.timeoutSeconds() * 1000, REPLY_TIMEOUT_CAP_MS))
          .exchange(baseUrl + "/chat/completions", HttpMethod.POST, new HttpEntity<>(body, h), String.class)
          .getBody();
      long ms = System.currentTimeMillis() - t1;
      steps.add(replyStep(model, reply, ms));
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
    return result(steps, models, baseUrl, model);
  }

  /** The reply's own model and form: a different model answering, or a reasoning model. */
  Step replyStep(String asked, String reply, long ms) {
    String answered = null;
    boolean reasoning = false;
    try {
      JsonNode r = reply == null ? null : objectMapper.readTree(reply);
      if (r != null) {
        answered = r.path("model").asText(null);
        JsonNode msg = r.path("choices").path(0).path("message");
        String thought = msg.path("reasoning_content").asText(msg.path("reasoning").asText(""));
        reasoning = !thought.isBlank() || msg.path("content").asText("").contains("<think>");
      }
    } catch (Exception ignored) {
      // A reply that isn't JSON still counts as a reply.
    }
    String think = reasoning
        ? " It's a reasoning model: it thinks before it answers, so give it a large LLM_MAX_TOKENS (24000 or more) and a long LLM_TIMEOUT."
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
