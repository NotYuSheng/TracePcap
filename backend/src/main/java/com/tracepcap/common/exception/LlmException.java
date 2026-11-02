package com.tracepcap.common.exception;

/** Exception thrown when the LLM service is unreachable or returns an unusable response */
public class LlmException extends RuntimeException {

  public enum ErrorCode { LLM_UNREACHABLE, LLM_TIMEOUT, OUTPUT_TRUNCATED, LLM_BAD_RESPONSE }

  private final ErrorCode errorCode;

  /** For a response the server sent but that can't be used. */
  public LlmException(String message) {
    super(message);
    this.errorCode = ErrorCode.LLM_BAD_RESPONSE;
  }

  public LlmException(String message, Throwable cause, ErrorCode errorCode) {
    super(message, cause);
    this.errorCode = errorCode;
  }

  public ErrorCode getErrorCode() {
    return errorCode;
  }
}
