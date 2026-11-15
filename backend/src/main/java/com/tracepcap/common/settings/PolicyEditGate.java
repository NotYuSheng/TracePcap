package com.tracepcap.common.settings;

/**
 * Whether the caller may edit a kind of policy, and why not (#915). Implemented by the governance
 * module, which owns permissions, so this module needn't depend on it.
 */
public interface PolicyEditGate {
  boolean canEdit(EditablePolicy.Kind kind);

  /** Why the caller can't, or null when they can. */
  String reason(EditablePolicy.Kind kind);
}
