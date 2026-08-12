package com.tracepcap.story.service;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.tracepcap.common.exception.ContextLengthExceededException;
import com.tracepcap.common.exception.LlmException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import com.tracepcap.config.LlmConfig;
import jakarta.annotation.PostConstruct;
import java.util.List;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

/** Client for communicating with OpenAI-compatible LLM APIs */
@Slf4j
@Service
public class LlmClient {

  private final LlmConfig llmConfig;
  private final RestTemplate llmRestTemplate;
  private final RestTemplate llmHealthCheckRestTemplate;

  public LlmClient(
      LlmConfig llmConfig,
      RestTemplate llmRestTemplate,
      RestTemplate llmHealthCheckRestTemplate) {
    this.llmConfig = llmConfig;
    this.llmRestTemplate = llmRestTemplate;
    this.llmHealthCheckRestTemplate = llmHealthCheckRestTemplate;
  }

  private static final Pattern PATTERN_PROMPT_TOKENS = Pattern.compile("\\((\\d+) in the messages");
  private static final Pattern PATTERN_CONTEXT_LENGTH = Pattern.compile("maximum context length is (\\d+)");
  private static final Pattern PATTERN_CONTEXT_LENGTH_ALT = Pattern.compile("context length is (\\d+)");

  private volatile Integer effectiveMaxTokens;
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
  public void initializeModelCapabilities() {
    // Set a safe default immediately so the app is usable before the background check finishes
    effectiveMaxTokens = llmConfig.getApi().getMaxTokens();

    Thread.ofVirtual()
        .name("llm-capability-check")
        .start(
            () -> {
              try {
                // If LLM_CONTEXT_LENGTH is explicitly configured, use it directly and skip
                // the /v1/models auto-detection call.
                if (llmConfig.getApi().getContextLength() != null) {
                  modelContextLength = llmConfig.getApi().getContextLength();
                  log.info(
                      "Using configured context length for model '{}': {}",
                      llmConfig.getApi().getModel(),
                      modelContextLength);
                } else {
                  log.info("Querying LLM server for model capabilities...");
                  ModelInfo modelInfo = queryModelCapabilities();
                  if (modelInfo != null && modelInfo.getContextLength() != null) {
                    modelContextLength = modelInfo.getContextLength();
                    log.info(
                        "Auto-detected context length for model '{}': {}",
                        llmConfig.getApi().getModel(),
                        modelContextLength);
                  } else {
                    log.warn(
                        "Could not determine model context length, using configured max_tokens: {}",
                        llmConfig.getApi().getMaxTokens());
                  }
                }

                if (modelContextLength != null) {
                  // Guard: cap effectiveMaxTokens so it never exceeds 80% of the context window.
                  // LLM_MAX_TOKENS controls response length; this guard prevents accidentally
                  // reserving more tokens for the response than the context window can support.
                  int recommendedMaxTokens = (int) (modelContextLength * 0.8);
                  effectiveMaxTokens =
                      Math.min(llmConfig.getApi().getMaxTokens(), recommendedMaxTokens);

                  log.info(
                      "Model '{}': context_length={}, configured_max_tokens={}, effective_max_tokens={}",
                      llmConfig.getApi().getModel(),
                      modelContextLength,
                      llmConfig.getApi().getMaxTokens(),
                      effectiveMaxTokens);

                  if (llmConfig.getApi().getMaxTokens() > recommendedMaxTokens) {
                    log.warn(
                        "Configured LLM_MAX_TOKENS ({}) exceeds 80% of context window ({}). Using {} tokens for responses.",
                        llmConfig.getApi().getMaxTokens(),
                        modelContextLength,
                        effectiveMaxTokens);
                  }
                }
              } catch (Exception e) {
                log.warn(
                    "Failed to initialise model capabilities: {}. Using configured max_tokens: {}",
                    e.getMessage(),
                    llmConfig.getApi().getMaxTokens());
              }
            });
  }

  /** Query the LLM server for model information */
  private ModelInfo queryModelCapabilities() {
    try {
      String url = llmConfig.getApi().getBaseUrl() + "/models";

      HttpHeaders headers = new HttpHeaders();
      headers.setBearerAuth(llmConfig.getApi().getApiKey());
      HttpEntity<Void> entity = new HttpEntity<>(headers);

      ResponseEntity<ModelsResponse> response =
          llmRestTemplate.exchange(url, HttpMethod.GET, entity, ModelsResponse.class);

      if (response.getBody() != null && response.getBody().getData() != null) {
        // Find the configured model in the response
        String configuredModel = llmConfig.getApi().getModel();
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
      String url = llmConfig.getApi().getBaseUrl() + "/models";
      HttpHeaders headers = new HttpHeaders();
      headers.setBearerAuth(llmConfig.getApi().getApiKey());
      HttpEntity<Void> entity = new HttpEntity<>(headers);
      llmHealthCheckRestTemplate.exchange(url, HttpMethod.GET, entity, String.class);
      log.debug("LLM health check passed");
    } catch (Exception e) {
      log.warn("LLM pre-flight health check failed: {}", e.getMessage());
      throw new LlmException(
          "LLM server is not reachable: " + e.getMessage(), e, LlmException.ErrorCode.LLM_UNREACHABLE);
    }
  }

  /** Get the effective max tokens (adjusted based on model capabilities) */
  public Integer getEffectiveMaxTokens() {
    return effectiveMaxTokens != null ? effectiveMaxTokens : llmConfig.getApi().getMaxTokens();
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
    String content = message.getContent();
    if (content == null) throw new LlmException("Empty response from LLM API");
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
      return message.getContent() != null
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

  /** Plain completion that tolerates a null message content (used on fallback paths). */
  private String sendForContent(String systemPrompt, String userPrompt) {
    Message message =
        post(buildRequest(systemPrompt, userPrompt, null, null), systemPrompt, userPrompt);
    if (message.getContent() == null) throw new LlmException("Empty response from LLM API");
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
    String mode = llmConfig.getApi().getToolCalling();
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
    if (modelContextLength != null) {
      int estimatedPromptTokens = (systemPrompt.length() + userPrompt.length()) / 2;
      int responseReserve = getEffectiveMaxTokens();
      if (estimatedPromptTokens + responseReserve > modelContextLength) {
        log.warn(
            "Pre-flight check: estimated prompt ({} tokens) + response reserve ({} tokens) exceeds context length ({}). Failing early.",
            estimatedPromptTokens, responseReserve, modelContextLength);
        throw new ContextLengthExceededException(estimatedPromptTokens, modelContextLength, userPrompt);
      }
    }

    checkReachable();
  }

  private ChatCompletionRequest buildRequest(
      String systemPrompt, String userPrompt, List<Tool> tools, String toolChoice) {
    return ChatCompletionRequest.builder()
        .model(llmConfig.getApi().getModel())
        .messages(List.of(new Message("system", systemPrompt), new Message("user", userPrompt)))
        .temperature(llmConfig.getApi().getTemperature())
        .maxTokens(getEffectiveMaxTokens())
        .tools(tools)
        .toolChoice(toolChoice)
        .build();
  }

  /**
   * POST a chat completion and return the first choice's message, preserving the error
   * classification the callers depend on.
   */
  private Message post(ChatCompletionRequest request, String systemPrompt, String userPrompt) {
    try {
      log.info("Sending request to LLM API: {}", llmConfig.getApi().getBaseUrl());
      log.debug(
          "Generating completion with max_tokens: {}, tools: {}",
          getEffectiveMaxTokens(),
          request.getTools() == null ? 0 : request.getTools().size());

      HttpHeaders headers = new HttpHeaders();
      headers.setContentType(MediaType.APPLICATION_JSON);
      headers.setBearerAuth(llmConfig.getApi().getApiKey());

      HttpEntity<ChatCompletionRequest> entity = new HttpEntity<>(request, headers);

      String url = llmConfig.getApi().getBaseUrl() + "/chat/completions";
      ResponseEntity<ChatCompletionResponse> response =
          llmRestTemplate.exchange(url, HttpMethod.POST, entity, ChatCompletionResponse.class);

      if (response.getBody() != null
          && response.getBody().getChoices() != null
          && !response.getBody().getChoices().isEmpty()) {

        var choice = response.getBody().getChoices().get(0);
        if (choice.getMessage() == null) throw new LlmException("Empty response from LLM API");
        return choice.getMessage();
      }

      throw new LlmException("Empty response from LLM API");

    } catch (LlmException e) {
      throw e;
    } catch (Exception e) {
      // Detect context-length exceeded errors.
      // Primary: OpenAI-compatible "maximum context length" message with token counts.
      // Fallback: any HTTP 400 whose message hints at context/token overflow — different
      // providers (Ollama, LM Studio, vLLM) use varying formats so regex may not match.
      String msg = e.getMessage() != null ? e.getMessage() : "";
      boolean isHttp400 = msg.contains("400");
      boolean looksLikeContextError = msg.contains("maximum context length")
          || msg.contains("context_length_exceeded")
          || msg.contains("context window")
          || msg.contains("token limit");
      if (looksLikeContextError) {
        int promptTokens = parseGroup(msg, PATTERN_PROMPT_TOKENS);
        int contextTokens = parseGroup(msg, PATTERN_CONTEXT_LENGTH);
        if (contextTokens == 0) contextTokens = parseGroup(msg, PATTERN_CONTEXT_LENGTH_ALT);
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
    private List<Choice> choices;
  }

  /** Choice in the response */
  @Data
  private static class Choice {
    private Message message;
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

    @JsonProperty("context_length")
    private Integer contextLength;

    @JsonProperty("max_tokens")
    private Integer maxTokens;
  }
}
