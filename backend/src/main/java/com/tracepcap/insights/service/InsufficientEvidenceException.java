package com.tracepcap.insights.service;

public class InsufficientEvidenceException extends RuntimeException {
  public InsufficientEvidenceException(String message) {
    super(message);
  }
}
