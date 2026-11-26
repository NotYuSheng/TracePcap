package com.tracepcap.story.service;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.tracepcap.common.exception.ContextLengthExceededException;
import com.tracepcap.common.exception.LlmException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import com.tracepcap.common.settings.LlmSettings;
import com.tracepcap.config.LlmConfig;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import jakarta.annotation.PostConstruct;
import java.util.List;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;

/** Client for communicating with OpenAI-compatible LLM APIs */
@Slf4j
@Service
public class LlmClient {

  private final LlmConfig llmConfig;
  private final LlmSettings settings;
  private final RestTemplate llmHealthCheckRestTemplate;

  public LlmClient(
      LlmConfig llmConfig,
      LlmSettings settings,
      RestTemplate llmRestTemplate,
      RestTemplate llmHealthCheckRestTemplate) {
    this.llmConfig = llmConfig;
    this.settings = settings;
    this.llmHealthCheckRestTemplate = llmHealthCheckRestTemplate;
    // The deployment's client, built with the deployment's timeout; replaced if Settings changes it.
    this.generationTemplate = llmRestTemplate;
    this.generationTimeoutSeconds =
        llmConfig.getApi() != null && llmConfig.getApi().getTimeoutSeconds() != null
            ? llmConfig.getApi().getTimeoutSeconds()
            : 300;
  }

  /** The generation client, rebuilt when the timeout changes in Settings. */
  private volatile RestTemplate generationTemplate;
  private volatile int generationTimeoutSeconds;

  private RestTemplate llmRestTemplate() {
    int timeout = settings.timeoutSeconds();
    RestTemplate t = generationTemplate;
    if (timeout != generationTimeoutSeconds) {
      SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
      factory.setConnectTimeout(timeout * 1000);
      factory.setReadTimeout(timeout * 1000);
      t = new RestTemplate(factory);
      generationTemplate = t;
      generationTimeoutSeconds = timeout;
    }
    return t;
  }

  /**
   * What the capabilities below were worked out for: the server, model and max tokens. When any of
   * them changes in Settings, they're worked out again (and what the old server said about tool
   * calling is forgotten), so a new server isn't judged by the old one's limits.
   */
  private volatile String capabilitiesFor;

  private void refreshCapabilitiesIfChanged() {
    String key = settings.baseUrl() + "|" + settings.model() + "|" + settings.maxTokens();
    if (key.equals(capabilitiesFor)) return;
    synchronized (this) {
      if (key.equals(capabilitiesFor)) return;
      capabilitiesFor = key;
      // LLM_CONTEXT_LENGTH, when set, wins over what the server says, now and later.
      modelContextLength = configuredContextLength();
      serverMaxOutput = null;
      toolCallingSupported = null;
      toolChoiceRequiredSupported = true;
      servedModel = null;
      // The name alone, at once (an embedding model says so); the server's own word follows.
      profile = ModelProfiles.fromName(settings.model());
      initializeModelCapabilities();
    }
  }

  private static final Pattern PATTERN_PROMPT_TOKENS = Pattern.compile("\\((\\d+) in the messages");
  private static final Pattern PATTERN_CONTEXT_LENGTH = Pattern.compile("maximum context length is (\\d+)");
  private static final Pattern PATTERN_CONTEXT_LENGTH_ALT = Pattern.compile("context length is (\\d+)");
  /** vLLM, GPUStack: "max_tokens=… cannot be greater than max_model_len=max_total_tokens=262144". */
  private static final Pattern PATTERN_MAX_MODEL_LEN =
      Pattern.compile("max_model_len(?:=max_total_tokens)?=(\\d+)");
  /** OpenAI and its kin cap the reply on its own: "supports at most 16384 completion tokens". */
  /** llama.cpp's error body: {@code "n_ctx": 8192}, the context it runs with. */
  private static final Pattern PATTERN_N_CTX = Pattern.compile("\"n_ctx\"\\s*:\\s*(\\d+)");
  private static final Pattern PATTERN_N_PROMPT_TOKENS = Pattern.compile("\"n_prompt_tokens\"\\s*:\\s*(\\d+)");
  private static final Pattern PATTERN_MAX_OUTPUT = Pattern.compile("at most (\\d+) completion tokens");

  /** Asked for by the context-length probe: more than any model's context. */
  static final int PROBE_MAX_TOKENS = 100_000_000;
  /** Room kept between prompt and reply for the chat template's own tokens. */
  static final int TEMPLATE_MARGIN = 64;
  /** The least reply worth asking for: a prompt that leaves less than this is too large. */
  static final int MIN_REPLY_TOKENS = 1024;
  /**
   * A reply's budget when neither the context nor a ceiling is known. Some servers (TGI) give a
   * request without {@code max_tokens} only a hundred or so; a reply cut off at this is asked again
   * without a cap.
   */
  static final int FALLBACK_REPLY_TOKENS = 8192;

  /** The most the server lets one reply be, apart from the context, when it said so. */
  private volatile Integer serverMaxOutput;

  /** What the configured model is (chat, vision, embedding) and whether it takes tools. */
  private volatile ModelProfiles.Profile profile;

  /** The model the server says answered the last call; servers that ignore the name differ. */
  private volatile String servedModel;

  private static final com.fasterxml.jackson.databind.ObjectMapper JSON = new com.fasterxml.jackson.databind.ObjectMapper();
  private volatile Integer modelContextLength;

  /**
   * Whether the server accepts {@code tools}. {@code null} = not yet observed; set on the first
   * tool-enabled call and sticky thereafter, so one rejection does not cost a failed request per
   * story. Ignored when {@code LLM_TOOL_CALLING} pins the mode to {@code on} or {@code off}.
   */
  private volatile Boolean toolCallingSupported;

  /**
   * Whether the server accepts {@code tool_choice: "required"}. Servers that support tools do not
   * all support forcing one; those fall back to {@code "auto"} rather than losing tools entirely.
   */
  private volatile boolean toolChoiceRequiredSupported = true;

  private static final String TOOL_CALLING_ON = "on";
  private static final String TOOL_CALLING_OFF = "off";

  /**
   * Query the LLM server for model capabilities on startup. Runs in a background thread so it does
   * not delay application startup when the LLM server is unavailable.
   */
  @PostConstruct
  public void start() {
    refreshCapabilitiesIfChanged();
  }

  private Integer configuredContextLength() {
    return llmConfig.getApi() == null ? null : llmConfig.getApi().getContextLength();
  }

  private void initializeModelCapabilities() {
    // What this check is for: its findings are dropped if Settings has moved on by the time they come.
    String forKey = capabilitiesFor;
    Thread.ofVirtual()
        .name("llm-capability-check")
        .start(
            () -> {
              try {
                describeModel();
                if (configuredContextLength() != null) {
                  log.info("Using configured context length for model '{}': {}", settings.model(), configuredContextLength());
                  return;
                }
                ModelInfo modelInfo = queryModelCapabilities();
                Integer fromList = modelInfo == null ? null : modelInfo.contextLength();
                String how = "from /models";
                if (fromList == null && modelInfo != null && namesItsLimit(modelInfo.getOwnedBy())) {
                  fromList = probeContextLength(forKey);
                  how = "from the server's limit";
                }
                if (fromList != null && forKey.equals(capabilitiesFor)) {
                  modelContextLength = fromList;
                  log.info("Context length for model '{}' {}: {}", settings.model(), how, fromList);
                } else if (fromList == null) {
                  log.info(
                      "Context length for model '{}' unknown: replies get {} tokens{}",
                      settings.model(),
                      settings.maxTokens() > 0 ? settings.maxTokens() : FALLBACK_REPLY_TOKENS,
                      settings.maxTokens() > 0 ? " (LLM_MAX_TOKENS)" : ", and a reply cut off is asked again uncapped");
                }
              } catch (Exception e) {
                log.warn("Failed to initialise model capabilities: {}", e.getMessage());
              }
            });
  }

  /**
   * Servers that refuse an impossible {@code max_tokens} before generating and name their limit
   * when they do. Others (LM Studio, Ollama, llama.cpp) would start generating, so they aren't
   * asked.
   */
  static boolean namesItsLimit(String ownedBy) {
    if (ownedBy == null) return false;
    String o = ownedBy.toLowerCase(java.util.Locale.ROOT);
    return o.contains("gpustack") || o.contains("vllm") || o.contains("sglang");
  }

  /**
   * The context length, from the server's refusal of an impossible {@code max_tokens}: vLLM,
   * GPUStack and SGLang name their limit when refusing one ("cannot be greater than
   * max_model_len=262144"), and refuse before generating; only those are asked ({@link
   * #namesItsLimit}). Null when nothing could be learnt.
   */
  Integer probeContextLength(String forKey) {
    Probed p = probe(llmHealthCheckRestTemplate, settings.baseUrl(), settings.apiKey(), settings.model());
    if (p.maxOutput() != null && forKey != null && forKey.equals(capabilitiesFor)) serverMaxOutput = p.maxOutput();
    return p.contextLength();
  }

  /** What a server's refusal of an impossible reply said about its limits; nulls when nothing. */
  record Probed(Integer contextLength, Integer maxOutput) {}

  /**
   * Asks for an impossible {@code max_tokens} and reads the limits from the refusal. Only for
   * servers that refuse before generating ({@link #namesItsLimit}); shared with the connection test.
   */
  static Probed probe(RestTemplate template, String baseUrl, String apiKey, String model) {
    try {
      HttpHeaders headers = new HttpHeaders();
      headers.setContentType(MediaType.APPLICATION_JSON);
      if (apiKey != null && !apiKey.isBlank()) headers.setBearerAuth(apiKey);
      ChatCompletionRequest probe =
          ChatCompletionRequest.builder()
              .model(model)
              .messages(List.of(new Message("user", "Reply with OK.")))
              .maxTokens(PROBE_MAX_TOKENS)
              .build();
      template.exchange(baseUrl + "/chat/completions", HttpMethod.POST, new HttpEntity<>(probe, headers), String.class);
    } catch (HttpStatusCodeException e) {
      String body = e.getResponseBodyAsString();
      int ctx = contextLengthIn(body);
      int out = parseGroup(body, PATTERN_MAX_OUTPUT);
      return new Probed(ctx > 0 ? ctx : null, out > 0 ? out : null);
    } catch (Exception e) {
      log.debug("Context-length probe got no answer: {}", e.getMessage());
    }
    return new Probed(null, null);
  }

  /** The context length a {@code /models} entry gives, from whichever field its server uses. */
  static Integer contextLengthOf(com.fasterxml.jackson.databind.JsonNode entry) {
    if (entry == null) return null;
    for (String f : List.of("context_length", "max_model_len", "max_context_length")) {
      if (entry.path(f).canConvertToInt() && entry.path(f).asInt() > 0) return entry.path(f).asInt();
    }
    return null;
  }


  /** Query the LLM server for model information */
  private ModelInfo queryModelCapabilities() {
    try {
      String url = settings.baseUrl() + "/models";

      HttpHeaders headers = new HttpHeaders();
      headers.setBearerAuth(settings.apiKey());
      HttpEntity<Void> entity = new HttpEntity<>(headers);

      // The short-timeout client: listing models is quick, and a slow server shouldn't hold this.
      ResponseEntity<ModelsResponse> response =
          llmHealthCheckRestTemplate.exchange(url, HttpMethod.GET, entity, ModelsResponse.class);

      if (response.getBody() != null && response.getBody().getData() != null) {
        // Find the configured model in the response
        String configuredModel = settings.model();
        for (ModelInfo model : response.getBody().getData()) {
          if (model.getId() != null && model.getId().equals(configuredModel)) {
            return model;
          }
        }

        // If exact match not found, return first model
        if (!response.getBody().getData().isEmpty()) {
          ModelInfo firstModel = response.getBody().getData().get(0);
          log.warn(
              "Configured model '{}' not found in models list. Using first available model: '{}'",
              configuredModel,
              firstModel.getId());
          return firstModel;
        }
      }
    } catch (Exception e) {
      log.debug("Error querying /models endpoint: {}", e.getMessage());
    }

    return null;
  }

  /**
   * Pre-flight reachability check using a short 2s timeout. Throws LLM_UNREACHABLE immediately
   * if the LLM server cannot be reached, so the user gets a fast failure rather than waiting for
   * the full generation timeout.
   */
  private void checkReachable() {
    try {
      String url = settings.baseUrl() + "/models";
      HttpHeaders headers = new HttpHeaders();
      headers.setBearerAuth(settings.apiKey());
      HttpEntity<Void> entity = new HttpEntity<>(headers);
      llmHealthCheckRestTemplate.exchange(url, HttpMethod.GET, entity, String.class);
      log.debug("LLM health check passed");
    } catch (HttpStatusCodeException e) {
      log.warn("LLM pre-flight health check rejected: {}", e.getMessage());
      throw new LlmException(
          "LLM server rejected the request: " + e.getMessage(),
          e,
          LlmException.ErrorCode.LLM_BAD_RESPONSE);
    } catch (Exception e) {
      log.warn("LLM pre-flight health check failed: {}", e.getMessage());
      throw new LlmException(
          "LLM server is not reachable: " + e.getMessage(), e, LlmException.ErrorCode.LLM_UNREACHABLE);
    }
  }

  /**
   * The model that writes the answers, for recording on a story: the one the server says answered
   * when that isn't the one configured (a server that serves whatever it has loaded), else the
   * configured one.
   */
  public String currentModel() {
    String served = servedModel;
    return served != null && !ModelProfiles.sameModel(settings.model(), served) ? served : settings.model();
  }

  /** A sentence when the server answered with another model than the configured one, else null. */
  public String modelMismatch() {
    String served = servedModel;
    if (served == null || ModelProfiles.sameModel(settings.model(), served)) return null;
    return "Answered by " + served + ", not " + settings.model()
        + ": the LLM server uses the model it has loaded. Load " + settings.model() + " there, or set the model to " + served + ".";
  }

  /** Asks the server what the configured model is; a model it says takes no tools isn't offered them. */
  private void describeModel() {
    // Its own short-timeout client: best-effort, and kept off the health check's path.
    org.springframework.http.client.SimpleClientHttpRequestFactory f = new org.springframework.http.client.SimpleClientHttpRequestFactory();
    f.setConnectTimeout(3_000);
    f.setReadTimeout(5_000);
    ModelProfiles.Profile p = ModelProfiles.describe(
        new RestTemplate(f), JSON, settings.baseUrl(), settings.apiKey(), settings.model());
    profile = p;
    if (p.fromServer()) {
      log.info("LLM model {}: {}{}", settings.model(), p.kind(),
          p.toolUse() == null ? "" : p.toolUse() ? ", takes tools" : ", no tools");
    }
    if (Boolean.FALSE.equals(p.toolUse()) && isAutoToolCalling()) toolCallingSupported = Boolean.FALSE;
  }

  /**
   * How long a reply may be, for a prompt of this many tokens: what the context has left after it,
   * under LLM_MAX_TOKENS when that's set (0 = no ceiling) and under the server's own reply cap.
   * When none of them is known, {@link #FALLBACK_REPLY_TOKENS}.
   */
  Integer outputBudget(int promptTokens) {
    Integer ctx = modelContextLength;
    Integer cap = serverMaxOutput;
    int ceiling = settings.maxTokens();
    Integer budget = ctx == null ? null : Math.max(ctx - promptTokens - TEMPLATE_MARGIN, MIN_REPLY_TOKENS);
    if (ceiling > 0) budget = budget == null ? ceiling : Math.min(budget, ceiling);
    if (cap != null) budget = budget == null ? cap : Math.min(budget, cap);
    return budget == null ? FALLBACK_REPLY_TOKENS : budget;
  }

  /** Whether the budget is only the fallback: nothing about this server's limits is known. */
  private boolean budgetIsAGuess() {
    return modelContextLength == null && serverMaxOutput == null && settings.maxTokens() <= 0;
  }

  /** The request's size in tokens, guessed high: every message, tool schema and call, as sent. */
  static int estimateTokens(ChatCompletionRequest request) {
    try {
      return estimateTokens(JSON.writeValueAsString(request));
    } catch (Exception e) {
      return estimateTokens(request.getMessages().stream().map(Message::getContent).toArray(String[]::new));
    }
  }

  /** Sets the request's budget from its own size. */
  private ChatCompletionRequest sized(ChatCompletionRequest request) {
    request.setMaxTokens(outputBudget(estimateTokens(request)));
    return request;
  }

  /** Tests only: the limits, as if the server had named them. */
  void assumeLimits(Integer contextLength, Integer maxOutput) {
    refreshCapabilitiesIfChanged();
    modelContextLength = contextLength;
    serverMaxOutput = maxOutput;
  }

  /** The prompt's size in tokens, guessed high: ~2 chars a token for logs, JSON and hex. */
  static int estimateTokens(String... parts) {
    long chars = 0;
    for (String p : parts) chars += p == null ? 0 : p.length();
    return (int) Math.min(Integer.MAX_VALUE, chars / 2);
  }

  /** Get the model's context length */
  public Integer getModelContextLength() {
    return modelContextLength;
  }

  /**
   * Generate a completion from the LLM
   *
   * @param systemPrompt the system prompt
   * @param userPrompt the user prompt
   * @return the generated text
   */
  public String generateCompletion(String systemPrompt, String userPrompt) {
    preflight(systemPrompt, userPrompt);

    Message message =
        post(buildRequest(systemPrompt, userPrompt, null, null), systemPrompt, userPrompt);
    String content = requireContent(message);
    log.info("Successfully received LLM response, length: {}", content.length());
    return content;
  }

  /**
   * Generate a completion with {@code tools} declared, so a supporting server constrains generation
   * to the tool's JSON schema instead of letting the model free-type JSON (#623).
   *
   * <p>Degrades rather than fails. If tool calling is disabled, unsupported, or rejected by the
   * server, the same prompts are sent as an ordinary completion and the result comes back as {@link
   * LlmToolResponse#freeText}, which callers must be prepared to parse themselves — the offline
   * requirement means we cannot assume a well-behaved hosted API on the other end.
   *
   * @param systemPrompt the system prompt
   * @param userPrompt the user prompt
   * @param tools tools the model may call
   * @return either schema-constrained tool calls or free text
   */
  public LlmToolResponse generateWithTools(
      String systemPrompt, String userPrompt, List<LlmToolSpec> tools) {

    preflight(systemPrompt, userPrompt);

    if (tools == null || tools.isEmpty() || !toolCallingEnabled()) {
      return LlmToolResponse.freeText(sendForContent(systemPrompt, userPrompt));
    }

    try {
      Message message = postWithTools(systemPrompt, userPrompt, tools);
      List<LlmToolResponse.ToolCall> calls = extractToolCalls(message);

      if (!calls.isEmpty()) {
        toolCallingSupported = Boolean.TRUE;
        log.info("LLM returned {} schema-constrained tool call(s)", calls.size());
        return LlmToolResponse.constrained(calls, message.getContent());
      }

      // Request accepted, tools ignored: the server does not implement them (or the model chose
      // not to call one). Remember it, and use whatever text came back.
      log.warn("LLM accepted tools but returned no tool_calls — falling back to free-text parsing");
      if (isAutoToolCalling()) toolCallingSupported = Boolean.FALSE;
      return hasContent(message)
          ? LlmToolResponse.freeText(message.getContent())
          : LlmToolResponse.freeText(sendForContent(systemPrompt, userPrompt));

    } catch (RuntimeException e) {
      if (!isAutoToolCalling() || !looksLikeToolsUnsupported(e)) throw e;
      log.warn(
          "LLM server rejected the tool-calling request ({}) — disabling tools and retrying as free text",
          e.getMessage());
      toolCallingSupported = Boolean.FALSE;
      return LlmToolResponse.freeText(sendForContent(systemPrompt, userPrompt));
    }
  }

  /**
   * Send a tool-enabled request, downgrading {@code tool_choice} from {@code required} to {@code
   * auto} once if the server rejects forcing a call. Servers that implement {@code tools} do not all
   * implement {@code tool_choice}, and losing the forced call is far cheaper than losing tools.
   */
  private Message postWithTools(String systemPrompt, String userPrompt, List<LlmToolSpec> tools) {
    List<Tool> wireTools = tools.stream().map(Tool::of).toList();
    if (toolChoiceRequiredSupported) {
      try {
        return post(
            buildRequest(systemPrompt, userPrompt, wireTools, "required"), systemPrompt, userPrompt);
      } catch (RuntimeException e) {
        if (!looksLikeToolsUnsupported(e)) throw e;
        log.warn("LLM server rejected tool_choice=required — retrying with tool_choice=auto");
        toolChoiceRequiredSupported = false;
      }
    }
    return post(buildRequest(systemPrompt, userPrompt, wireTools, "auto"), systemPrompt, userPrompt);
  }

  /** Plain completion, used on the paths that fall back from tool calling. */
  private String sendForContent(String systemPrompt, String userPrompt) {
    return requireContent(
        post(buildRequest(systemPrompt, userPrompt, null, null), systemPrompt, userPrompt));
  }

  private static boolean hasContent(Message message) {
    return message.getContent() != null && !message.getContent().isBlank();
  }

  /**
   * The reply's text, or a typed failure. Blank counts as empty: some servers send {@code ""} rather
   * than {@code null}, which would otherwise surface later as a parse failure in the caller.
   */
  private static String requireContent(Message message) {
    if (!hasContent(message)) throw new LlmException("Empty response from LLM API");
    return message.getContent();
  }

  /** Whether tool calling should be attempted, honouring the configured mode. */
  private boolean toolCallingEnabled() {
    String mode = toolCallingMode();
    if (TOOL_CALLING_OFF.equals(mode)) return false;
    if (TOOL_CALLING_ON.equals(mode)) return true;
    return !Boolean.FALSE.equals(toolCallingSupported);
  }

  private boolean isAutoToolCalling() {
    String mode = toolCallingMode();
    return !TOOL_CALLING_ON.equals(mode) && !TOOL_CALLING_OFF.equals(mode);
  }

  private String toolCallingMode() {
    String mode = settings.toolCalling();
    return mode == null ? "auto" : mode.trim().toLowerCase();
  }

  /**
   * Whether a failure reads as "this server does not do tool calling" rather than a real outage.
   * Backends disagree on wording, so this matches on the request fields being named at all — a 400
   * mentioning {@code tools} is the server telling us it could not parse what we sent.
   */
  private static boolean looksLikeToolsUnsupported(Throwable e) {
    String msg = e.getMessage() != null ? e.getMessage().toLowerCase() : "";
    if (e.getCause() != null && e.getCause().getMessage() != null) {
      msg = msg + " " + e.getCause().getMessage().toLowerCase();
    }
    boolean namesToolFields =
        msg.contains("tool") || msg.contains("function") || msg.contains("response_format");
    return namesToolFields && (msg.contains("400") || msg.contains("404") || msg.contains("422"));
  }

  private List<LlmToolResponse.ToolCall> extractToolCalls(Message message) {
    if (message.getToolCalls() == null) return List.of();
    return message.getToolCalls().stream()
        .filter(c -> c.getFunction() != null && c.getFunction().getName() != null)
        .map(
            c ->
                new LlmToolResponse.ToolCall(
                    c.getFunction().getName(),
                    c.getFunction().getArguments() != null ? c.getFunction().getArguments() : "{}"))
        .toList();
  }

  /**
   * Pre-flight context-length check — fail immediately without calling the LLM server. Use ~2
   * chars/token (conservative) rather than 4 — technical content such as network logs, JSON, and hex
   * strings tokenises more densely and can easily fall below 3 chars/token. A tighter estimate means
   * fewer false passes that still fail at the server side. Only fires when modelContextLength is
   * known (LLM_CONTEXT_LENGTH set or auto-detected).
   *
   * <p>Also runs the reachability probe, so users get an instant LLM_UNREACHABLE instead of waiting
   * for the full generation timeout.
   */
  private void preflight(String systemPrompt, String userPrompt) {
    // Settings may have changed since the last call: a new server or model is checked afresh.
    refreshCapabilitiesIfChanged();
    ModelProfiles.Profile p = profile;
    if (p != null && !p.canChat()) {
      throw new LlmException(
          "The model set for the LLM (" + settings.model() + ") is an embedding model: it turns text into"
              + " numbers for search and can't write answers. Pick a chat model in Settings › LLM.",
          null,
          LlmException.ErrorCode.LLM_BAD_RESPONSE);
    }
    if (modelContextLength != null) {
      int estimatedPromptTokens = estimateTokens(systemPrompt, userPrompt);
      // The reply's budget shrinks to fit, so only a prompt that leaves no useful room fails here.
      int responseReserve = MIN_REPLY_TOKENS;
      if (estimatedPromptTokens + responseReserve > modelContextLength) {
        log.warn(
            "Pre-flight check: estimated prompt ({} tokens) + response reserve ({} tokens) exceeds context length ({}). Failing early.",
            estimatedPromptTokens, responseReserve, modelContextLength);
        throw new ContextLengthExceededException(estimatedPromptTokens, modelContextLength, userPrompt);
      }
    }

    checkReachable();
  }

  // ── Multi-turn conversation with tools (the capture chat) ──────────────────────────────────

  /** A tool the model asked to run, with the id its result must carry back. */
  public record CallRequest(String id, String name, String argumentsJson) {}

  /**
   * One message of a tool-using conversation: system, user, assistant (with the calls it made, if
   * any) or tool (one call's result).
   */
  public record Turn(String role, String content, List<CallRequest> calls, String toolCallId) {
    public static Turn system(String content) {
      return new Turn("system", content, null, null);
    }

    public static Turn user(String content) {
      return new Turn("user", content, null, null);
    }

    public static Turn assistant(String content, List<CallRequest> calls) {
      return new Turn("assistant", content, calls, null);
    }

    public static Turn tool(String toolCallId, String content) {
      return new Turn("tool", content, null, toolCallId);
    }
  }

  /**
   * The model's reply: tools to run, or its answer. {@code toolsOffered} is false when the request
   * went without tools (tool calling off, or the server doesn't support it), so the caller knows
   * the answer came from the context alone.
   */
  public record Reply(String content, List<CallRequest> calls, boolean toolsOffered) {}

  /**
   * One step of a conversation the caller keeps: send every turn so far, get the next reply. Tools
   * are offered with {@code tool_choice=auto}, so answering without one is a normal reply and says
   * nothing about the server's support; only a server rejecting the tools field marks it unsupported.
   */
  public Reply converse(List<Turn> turns, List<LlmToolSpec> tools) {
    String all = turns.stream().map(t -> t.content() == null ? "" : t.content()).reduce("", String::concat);
    preflight("", all);
    boolean offer = tools != null && !tools.isEmpty() && toolCallingEnabled();
    if (offer) {
      try {
        Message m = post(conversation(turns, tools.stream().map(Tool::of).toList()), "", all);
        List<CallRequest> calls = callsOf(m);
        if (!calls.isEmpty()) toolCallingSupported = Boolean.TRUE;
        return new Reply(m.getContent(), calls, true);
      } catch (RuntimeException e) {
        if (!isAutoToolCalling() || !looksLikeToolsUnsupported(e)) throw e;
        log.warn("LLM server rejected tools in the chat ({}) — answering without them", e.getMessage());
        toolCallingSupported = Boolean.FALSE;
      }
    }
    // Without tools, tool turns from earlier steps can't be sent; keep only the plain messages.
    List<Turn> plain = turns.stream().filter(t -> !"tool".equals(t.role()) && (t.calls() == null || t.calls().isEmpty())).toList();
    return new Reply(requireContent(post(conversation(plain, null), "", all)), List.of(), false);
  }

  /** "on", "off", or for auto: "supported", "unsupported" or "unknown" (not tried yet). */
  public String toolCallingStatus() {
    String mode = toolCallingMode();
    if (TOOL_CALLING_ON.equals(mode)) return "on";
    if (TOOL_CALLING_OFF.equals(mode)) return "off";
    if (toolCallingSupported == null) return "unknown";
    return toolCallingSupported ? "supported" : "unsupported";
  }

  private ChatCompletionRequest conversation(List<Turn> turns, List<Tool> tools) {
    List<Message> messages = new java.util.ArrayList<>();
    for (Turn t : turns) {
      Message m = new Message(t.role(), t.content());
      if (t.calls() != null && !t.calls().isEmpty()) {
        // Some servers require content on every message; an empty string satisfies them all.
        if (m.getContent() == null) m.setContent("");
        m.setToolCalls(t.calls().stream().map(c -> {
          ToolCall w = new ToolCall();
          w.setId(c.id());
          w.setType("function");
          FunctionCall f = new FunctionCall();
          f.setName(c.name());
          f.setArguments(c.argumentsJson());
          w.setFunction(f);
          return w;
        }).toList());
      }
      m.setToolCallId(t.toolCallId());
      messages.add(m);
    }
    return sized(ChatCompletionRequest.builder()
        .model(settings.model())
        .messages(messages)
        .temperature(settings.temperature())
        .tools(tools)
        .toolChoice(tools == null ? null : "auto")
        .build());
  }

  private static List<CallRequest> callsOf(Message message) {
    if (message.getToolCalls() == null) return List.of();
    List<CallRequest> out = new java.util.ArrayList<>();
    int i = 0;
    for (ToolCall c : message.getToolCalls()) {
      if (c.getFunction() == null || c.getFunction().getName() == null) continue;
      String id = c.getId() != null && !c.getId().isBlank() ? c.getId() : "call_" + (i++);
      out.add(new CallRequest(id, c.getFunction().getName(),
          c.getFunction().getArguments() != null ? c.getFunction().getArguments() : "{}"));
    }
    return out;
  }

  private ChatCompletionRequest buildRequest(
      String systemPrompt, String userPrompt, List<Tool> tools, String toolChoice) {
    return sized(ChatCompletionRequest.builder()
        .model(settings.model())
        .messages(List.of(new Message("system", systemPrompt), new Message("user", userPrompt)))
        .temperature(settings.temperature())
        .tools(tools)
        .toolChoice(toolChoice)
        .build());
  }

  /**
   * POST a chat completion and return the first choice's message, preserving the error
   * classification the callers depend on.
   */
  private Message post(ChatCompletionRequest request, String systemPrompt, String userPrompt) {
    return post(request, systemPrompt, userPrompt, false);
  }

  private Message post(
      ChatCompletionRequest request, String systemPrompt, String userPrompt, boolean retried) {
    try {
      log.info("Sending request to LLM API: {}", settings.baseUrl());
      log.debug(
          "Generating completion with max_tokens: {}, tools: {}",
          request.getMaxTokens() == null ? "(server's)" : request.getMaxTokens(),
          request.getTools() == null ? 0 : request.getTools().size());

      HttpHeaders headers = new HttpHeaders();
      headers.setContentType(MediaType.APPLICATION_JSON);
      headers.setBearerAuth(settings.apiKey());

      HttpEntity<ChatCompletionRequest> entity = new HttpEntity<>(request, headers);

      String url = settings.baseUrl() + "/chat/completions";
      ResponseEntity<ChatCompletionResponse> response =
          llmRestTemplate().exchange(url, HttpMethod.POST, entity, ChatCompletionResponse.class);

      if (response.getBody() != null
          && response.getBody().getChoices() != null
          && !response.getBody().getChoices().isEmpty()) {

        var choice = response.getBody().getChoices().get(0);
        // Deliberate guard: a "length" finish_reason means the model hit its output cap and the
        // response is truncated. Fail here with a clear, typed error instead of letting the partial
        // (invalid) JSON blow up later as a cryptic parse failure.
        if ("length".equalsIgnoreCase(choice.getFinishReason())) {
          // The budget came from a guess at the prompt's size; the server counted it. When the
          // real count leaves clearly more room, ask once more with that.
          Usage usage = response.getBody().getUsage();
          Integer roomier =
              usage == null || usage.getPromptTokens() == null ? null : outputBudget(usage.getPromptTokens());
          Integer asked = request.getMaxTokens();
          if (!retried && asked != null && roomier != null && roomier > asked + asked / 10) {
            log.info("Reply cut off at {} tokens; the prompt was {} tokens, so retrying with {}",
                asked, usage.getPromptTokens(), roomier);
            request.setMaxTokens(roomier);
            return post(request, systemPrompt, userPrompt, true);
          }
          // Nothing known about this server: the fallback was a guess, so let the server decide.
          if (!retried && asked != null && budgetIsAGuess()) {
            log.info("Reply cut off at the fallback {} tokens; retrying without max_tokens", asked);
            request.setMaxTokens(null);
            return post(request, systemPrompt, userPrompt, true);
          }
          throw new LlmException(truncatedMessage(asked), null, LlmException.ErrorCode.OUTPUT_TRUNCATED);
        }
        // Checked after the cap: a model that spends its budget reasoning can stop with no message.
        if (choice.getMessage() == null) throw new LlmException("Empty response from LLM API");
        noteServedModel(response.getBody().getModel());
        Message message = choice.getMessage();
        boolean calls = message.getToolCalls() != null && !message.getToolCalls().isEmpty();
        String content = stripThinking(message.getContent());
        boolean thought = (message.getReasoningContent() != null && !message.getReasoningContent().isBlank())
            || (message.getContent() != null && message.getContent().contains("<think>"));
        if (!calls && (content == null || content.isBlank()) && thought) {
          // A reasoning model that used its whole reply thinking.
          throw new LlmException(
              "The model spent its whole reply reasoning and never gave an answer. "
                  + (settings.maxTokens() > 0
                      ? "Raise LLM_MAX_TOKENS (reasoning models need 24000 or more), or set it to 0 to"
                          + " let the reply use the whole context, and raise LLM_TIMEOUT."
                      : "Raise LLM_TIMEOUT, or use a model with a larger context."),
              null,
              LlmException.ErrorCode.OUTPUT_TRUNCATED);
        }
        message.setContent(content);
        return message;
      }

      throw new LlmException("Empty response from LLM API");

    } catch (LlmException | ContextLengthExceededException e) {
      // Already classified, by this call or a retry inside it.
      throw e;
    } catch (Exception e) {
      // Detect context-length exceeded errors.
      // Primary: OpenAI-compatible "maximum context length" message with token counts.
      // Fallback: any HTTP 400 whose message hints at context/token overflow — different
      // providers (Ollama, LM Studio, vLLM) use varying formats so regex may not match.
      String msg = e.getMessage() != null ? e.getMessage() : "";
      if (e instanceof HttpStatusCodeException h) msg = msg + " " + h.getResponseBodyAsString();
      int prompt = parseGroup(msg, PATTERN_PROMPT_TOKENS);
      if (prompt == 0) prompt = parseGroup(msg, PATTERN_N_PROMPT_TOKENS);
      boolean learnt = learnLimits(msg);
      // Worth asking again only with something new: a limit, or the server's count of the prompt.
      if (!retried && request.getMaxTokens() != null && (learnt || prompt > 0)) {
        // The budget overshot a limit the server has named; size it to that and ask again.
        Integer ctx = modelContextLength;
        boolean promptFits = prompt == 0 || ctx == null || prompt + MIN_REPLY_TOKENS <= ctx;
        Integer budget = outputBudget(prompt > 0 ? prompt : estimateTokens(request));
        if (promptFits && budget != null && budget < request.getMaxTokens()) {
          log.info("LLM refused max_tokens={}; retrying with {}", request.getMaxTokens(), budget);
          request.setMaxTokens(budget);
          return post(request, systemPrompt, userPrompt, true);
        }
      }
      boolean isHttp400 = msg.contains("400");
      boolean looksLikeContextError = msg.contains("maximum context length")
          || msg.contains("max_model_len")
          || msg.contains("exceed_context_size")
          || msg.contains("context_length_exceeded")
          || msg.contains("context window")
          || msg.contains("token limit");
      if (looksLikeContextError) {
        int promptTokens = parseGroup(msg, PATTERN_PROMPT_TOKENS);
        int contextTokens = contextLengthIn(msg);
        // If regex couldn't extract counts, use the pre-flight estimate as a best-effort value
        // so the UI shows something meaningful rather than "0 tokens".
        if (promptTokens == 0) {
          promptTokens = (systemPrompt.length() + userPrompt.length()) / 2;
        }
        if (contextTokens == 0 && modelContextLength != null) {
          contextTokens = modelContextLength;
        }
        throw new ContextLengthExceededException(promptTokens, contextTokens, userPrompt);
      }
      // Re-classify ambiguous HTTP 400s that don't match the patterns above
      if (isHttp400) {
        log.warn("LLM returned HTTP 400 — likely context length or bad request: {}", msg);
      } else {
        log.error("Error calling LLM API", e);
      }
      // The server answered, so this is not an outage (bad key, unknown model, server error)
      if (e instanceof HttpStatusCodeException) {
        throw new LlmException(
            "LLM server rejected the request: " + msg,
            e,
            LlmException.ErrorCode.LLM_BAD_RESPONSE);
      }
      // Distinguish read/generation timeouts from connection failures
      Throwable cause = e.getCause() != null ? e.getCause() : e;
      String causeMsg = cause.getMessage() != null ? cause.getMessage() : "";
      boolean isReadTimeout = cause instanceof java.net.SocketTimeoutException
          && causeMsg.contains("Read timed out");
      LlmException.ErrorCode code = isReadTimeout
          ? LlmException.ErrorCode.LLM_TIMEOUT
          : LlmException.ErrorCode.LLM_UNREACHABLE;
      throw new LlmException("Failed to reach the LLM service: " + e.getMessage(), e, code);
    }
  }

  /** Records which model answered, and says so once when it isn't the one asked for. */
  private void noteServedModel(String served) {
    if (served == null || served.isBlank()) return;
    String before = servedModel;
    servedModel = served;
    if (!served.equals(before) && !ModelProfiles.sameModel(settings.model(), served)) {
      log.warn("Asked the LLM for model '{}' but '{}' answered: the server uses the model it has loaded.",
          settings.model(), served);
    }
  }

  /**
   * The answer without a reasoning model's thinking: {@code <think>…</think>} blocks go, and an
   * unclosed {@code <think>} (the reply ended mid-thought) takes the rest with it.
   */
  static String stripThinking(String content) {
    if (content == null || !content.contains("<think>")) return content;
    String out = content.replaceAll("(?s)<think>.*?</think>", "");
    int open = out.indexOf("<think>");
    if (open >= 0) out = out.substring(0, open);
    return out.trim();
  }

  /**
   * Notes the context length or reply cap an error names. True when either is new.
   */
  private boolean learnLimits(String msg) {
    boolean learnt = false;
    int ctx = contextLengthIn(msg);
    // A configured LLM_CONTEXT_LENGTH stays; the server's prompt count still resizes the reply.
    if (ctx > 0 && configuredContextLength() == null && !Integer.valueOf(ctx).equals(modelContextLength)) {
      modelContextLength = ctx;
      learnt = true;
    }
    int out = parseGroup(msg, PATTERN_MAX_OUTPUT);
    if (out > 0 && !Integer.valueOf(out).equals(serverMaxOutput)) {
      serverMaxOutput = out;
      learnt = true;
    }
    return learnt;
  }

  /** The context length a server's message names, or 0. */
  static int contextLengthIn(String text) {
    if (text == null) return 0;
    int n = parseGroup(text, PATTERN_MAX_MODEL_LEN);
    if (n == 0) n = parseGroup(text, PATTERN_CONTEXT_LENGTH);
    if (n == 0) n = parseGroup(text, PATTERN_CONTEXT_LENGTH_ALT);
    if (n == 0) n = parseGroup(text, PATTERN_N_CTX);
    return n;
  }

  /** Why a reply was cut off, and what would let the next one finish. */
  private String truncatedMessage(Integer asked) {
    String size = asked == null ? "" : " (" + asked + " tokens)";
    String fix =
        settings.maxTokens() > 0 && asked != null && asked >= settings.maxTokens()
            ? "Raise LLM_MAX_TOKENS, or set it to 0 to let the reply use what the context has left"
            : "The prompt and reply filled the model's context. Use a model with a larger context";
    return "The model's response exceeded the output token budget" + size
        + " and was cut off before it was complete. " + fix
        + ", or for a story, reduce the amount to narrate (lower maxFindings / maxRiskMatrix).";
  }

  private static int parseGroup(String text, Pattern pattern) {
    Matcher m = pattern.matcher(text);
    return m.find() ? Integer.parseInt(m.group(1)) : 0;
  }

  /**
   * OpenAI Chat Completion Request format.
   *
   * <p>{@code NON_NULL}: a server that has never heard of {@code tools} must not receive {@code
   * "tools": null} — strict backends reject unknown fields outright, and the whole point of the
   * fallback path is to send exactly what the pre-#623 client sent.
   */
  @Data
  @lombok.Builder
  @com.fasterxml.jackson.annotation.JsonInclude(
      com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL)
  private static class ChatCompletionRequest {
    private String model;
    private List<Message> messages;
    private Double temperature;

    @JsonProperty("max_tokens")
    private Integer maxTokens;

    private List<Tool> tools;

    @JsonProperty("tool_choice")
    private String toolChoice;
  }

  /** Message in the conversation */
  @Data
  @lombok.NoArgsConstructor
  @com.fasterxml.jackson.annotation.JsonInclude(
      com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL)
  private static class Message {
    private String role;
    private String content;

    @JsonProperty("tool_calls")
    private List<ToolCall> toolCalls;

    @JsonProperty("tool_call_id")
    private String toolCallId;

    /** A reasoning model's thinking, on servers that send it apart from the answer. Never sent back. */
    @JsonProperty(value = "reasoning_content", access = com.fasterxml.jackson.annotation.JsonProperty.Access.WRITE_ONLY)
    private String reasoningContent;

    Message(String role, String content) {
      this.role = role;
      this.content = content;
    }
  }

  /** Tool declaration on the request ({@code {"type":"function","function":{...}}}) */
  @Data
  @lombok.AllArgsConstructor
  private static class Tool {
    private String type;
    private FunctionDefinition function;

    static Tool of(LlmToolSpec spec) {
      return new Tool(
          "function", new FunctionDefinition(spec.name(), spec.description(), spec.parameters()));
    }
  }

  /** Function half of a tool declaration */
  @Data
  @lombok.AllArgsConstructor
  private static class FunctionDefinition {
    private String name;
    private String description;
    private java.util.Map<String, Object> parameters;
  }

  /** Tool call on the response */
  @Data
  private static class ToolCall {
    private String id;
    private String type;
    private FunctionCall function;
  }

  /** Function half of a tool call — {@code arguments} is a JSON string, not an object */
  @Data
  private static class FunctionCall {
    private String name;
    private String arguments;
  }

  /** OpenAI Chat Completion Response format */
  @Data
  private static class ChatCompletionResponse {
    /** The model that answered, as the server names it. */
    private String model;

    private List<Choice> choices;

    private Usage usage;
  }

  /** The tokens the server counted. */
  @Data
  private static class Usage {
    @JsonProperty("prompt_tokens")
    private Integer promptTokens;
  }

  /** Choice in the response */
  @Data
  private static class Choice {
    private Message message;

    /** Why generation stopped: {@code "stop"} = complete, {@code "length"} = hit the token cap. */
    @JsonProperty("finish_reason")
    private String finishReason;
  }

  /** Models list response */
  @Data
  private static class ModelsResponse {
    private List<ModelInfo> data;
  }

  /** Model information */
  @Data
  private static class ModelInfo {
    private String id;
    private String object;
    private Long created;

    @JsonProperty("owned_by")
    private String ownedBy;

    /** LM Studio. */
    @JsonProperty("context_length")
    private Integer contextLength;

    /** vLLM. */
    @JsonProperty("max_model_len")
    private Integer maxModelLen;

    @JsonProperty("max_context_length")
    private Integer maxContextLength;

    @JsonProperty("max_tokens")
    private Integer maxTokens;

    /** The context length, from whichever field this server uses for it. */
    Integer contextLength() {
      if (contextLength != null) return contextLength;
      if (maxModelLen != null) return maxModelLen;
      // Not llama.cpp's meta.n_ctx_train: that's what the model was trained on, not what runs.
      return maxContextLength;
    }
  }
}
