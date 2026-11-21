package com.tracepcap.common.adjudication;

/**
 * Throws a 403 unless the caller may override an answer or change its evidence. The roles model
 * implements it (governance); this lives here so adjudication doesn't depend on that module.
 */
public interface AdjudicationEditGate {

  void requireEdit();
}
