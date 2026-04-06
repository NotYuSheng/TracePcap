package com.tracepcap.common.exception;

/** Exception thrown when the LLM service is unreachable or returns an error */
public class LlmException extends RuntimeException {

  public LlmException(String message) {
    super(message);
  }

  public LlmException(String message, Throwable cause) {
    super(message, cause);
  }
}
