package com.tracepcap.common.exception;

/** Thrown when the constructed LLM prompt exceeds the model's context window. */
public class ContextLengthExceededException extends RuntimeException {

  private final int promptTokens;
  private final int contextLength;
  private final String prompt;

  public ContextLengthExceededException(int promptTokens, int contextLength, String prompt) {
    super(String.format(
        "Prompt too large: %d tokens sent but model context window is %d tokens",
        promptTokens, contextLength));
    this.promptTokens = promptTokens;
    this.contextLength = contextLength;
    this.prompt = prompt;
  }

  public int getPromptTokens() { return promptTokens; }
  public int getContextLength() { return contextLength; }
  public String getPrompt() { return prompt; }
}
