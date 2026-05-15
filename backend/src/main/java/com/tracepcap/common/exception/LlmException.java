package com.lanturn.common.exception;

/** Exception thrown when the LLM service is unreachable or returns an error */
public class LlmException extends RuntimeException {

  public enum ErrorCode { LLM_UNREACHABLE, LLM_TIMEOUT }

  private final ErrorCode errorCode;

  public LlmException(String message) {
    super(message);
    this.errorCode = ErrorCode.LLM_UNREACHABLE;
  }

  public LlmException(String message, Throwable cause) {
    super(message, cause);
    this.errorCode = ErrorCode.LLM_UNREACHABLE;
  }

  public LlmException(String message, Throwable cause, ErrorCode errorCode) {
    super(message, cause);
    this.errorCode = errorCode;
  }

  public ErrorCode getErrorCode() {
    return errorCode;
  }
}
