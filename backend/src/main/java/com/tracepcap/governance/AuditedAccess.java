package com.tracepcap.governance;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * A read that is still an action worth recording: a download or export, which takes data out of
 * the application. {@link RequestAuditInterceptor} audits it like a write.
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface AuditedAccess {}
