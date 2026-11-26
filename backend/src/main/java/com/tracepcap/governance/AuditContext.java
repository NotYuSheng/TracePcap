package com.tracepcap.governance;

import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

/**
 * Lets a handler name what the current request acted on, for the automatic audit entry
 * ({@link RequestAuditInterceptor}): an upload knows its new capture's id and name only after the
 * work is done, and a delete knows the capture's name only before. A no-op outside a request.
 */
public final class AuditContext {

  static final String TARGET_ID = AuditContext.class.getName() + ".targetId";
  static final String NAME = AuditContext.class.getName() + ".name";
  /** Set when an explicit {@link AuditLogService#record} entry was written for this request. */
  static final String RECORDED = AuditContext.class.getName() + ".recorded";

  private AuditContext() {}

  /** What this request acted on: an id, and a name a person recognises (a file name, a label). */
  public static void describe(String targetId, String name) {
    RequestAttributes attrs = RequestContextHolder.getRequestAttributes();
    if (attrs == null) return;
    if (targetId != null) attrs.setAttribute(TARGET_ID, targetId, RequestAttributes.SCOPE_REQUEST);
    if (name != null) attrs.setAttribute(NAME, name, RequestAttributes.SCOPE_REQUEST);
  }

  static void markRecorded() {
    RequestAttributes attrs = RequestContextHolder.getRequestAttributes();
    if (attrs != null) attrs.setAttribute(RECORDED, Boolean.TRUE, RequestAttributes.SCOPE_REQUEST);
  }
}
