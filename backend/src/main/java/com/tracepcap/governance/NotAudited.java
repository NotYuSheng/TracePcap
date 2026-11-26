package com.tracepcap.governance;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * A write endpoint that changes nothing worth auditing: a preview, a query sent as POST, or a
 * person's own UI preferences. {@link RequestAuditInterceptor} records every other write. Say why
 * in {@link #value}, so the exemption can be reviewed.
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface NotAudited {
  /** Why this endpoint isn't audited. */
  String value();
}
