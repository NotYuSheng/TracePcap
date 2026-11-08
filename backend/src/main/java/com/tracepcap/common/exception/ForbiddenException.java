package com.tracepcap.common.exception;

/** The caller is identified but not allowed to do this (#915). Mapped to 403. */
public class ForbiddenException extends RuntimeException {
  public ForbiddenException(String message) {
    super(message);
  }
}
