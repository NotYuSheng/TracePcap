package com.lanturn.insights.service;

public class InsufficientEvidenceException extends RuntimeException {
  public InsufficientEvidenceException(String message) {
    super(message);
  }
}
