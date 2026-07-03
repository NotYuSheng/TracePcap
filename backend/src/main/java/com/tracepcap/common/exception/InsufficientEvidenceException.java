package com.tracepcap.common.exception;

/**
 * Thrown when a node's traffic signals are too sparse to make a meaningful AI role suggestion.
 * Mapped to 422 by {@link GlobalExceptionHandler}.
 */
public class InsufficientEvidenceException extends RuntimeException {
  public InsufficientEvidenceException(String message) {
    super(message);
  }
}
