package com.tracepcap.common.aijob;

/**
 * Whether the caller may cancel AI work someone else asked for. The roles model implements it
 * (governance); this lives here so the job queue doesn't depend on that module.
 */
public interface AiJobCancelGate {

  boolean mayCancelOthers();
}
