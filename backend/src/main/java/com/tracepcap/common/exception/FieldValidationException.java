package com.tracepcap.common.exception;

import java.util.Map;

/**
 * Validation that a bean annotation can't express (a regex that must compile, a valid CIDR, a
 * rule needing at least one criterion). Mapped to 400 with {@code validationErrors}, the same
 * shape as a {@code @Valid} failure, so the UI shows each message next to its field.
 */
public class FieldValidationException extends RuntimeException {
  private final Map<String, String> errors;

  public FieldValidationException(String message, Map<String, String> errors) {
    super(message);
    this.errors = Map.copyOf(errors);
  }

  public Map<String, String> getErrors() {
    return errors;
  }
}
