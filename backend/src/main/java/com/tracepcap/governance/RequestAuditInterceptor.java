package com.tracepcap.governance;

import com.tracepcap.config.WebConfig;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.multipart.MultipartHttpServletRequest;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.HandlerMapping;

/**
 * Every action a person takes is audited, not only the ones a service remembered to record. After
 * each API write (POST, PUT, PATCH, DELETE) that succeeded or was refused for lack of permission,
 * this writes an entry, unless the handler already wrote its own richer one (with before/after
 * values) through {@link AuditLogService#record}. Downloads and exports
 * ({@link AuditedAccess}) count too. Page views and other reads don't, and neither do endpoints
 * marked {@link NotAudited}.
 *
 * <p>The entry says who (the signed-in user, or "system"), what (the endpoint's own OpenAPI
 * summary, e.g. "Add a snapshot to a network", and an action key such as
 * {@code network.snapshots.create}), what it was done to (the first path id, or whatever the
 * handler named with {@link AuditContext#describe}), and the outcome (status; refusals are kept,
 * marked denied). Request bodies are never stored: they can hold secrets (an LLM key) and
 * captures' contents.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class RequestAuditInterceptor implements HandlerInterceptor {

  private static final Set<String> WRITES = Set.of("POST", "PUT", "PATCH", "DELETE");

  /** The first literal path segment, made a singular type, where plain de-pluralising reads badly. */
  private static final Map<String, String> TYPE_NAMES =
      Map.of("monitor", "network", "system", "system-setting", "filter", "filter", "tracer", "conversation");

  /**
   * Looked up when needed: a {@code @WebMvcTest} slice picks up interceptors but not the audit log,
   * and must still start.
   */
  private final org.springframework.beans.factory.ObjectProvider<AuditLogService> auditLogService;

  @Override
  public void afterCompletion(
      HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) {
    try {
      if (!(handler instanceof HandlerMethod method)) return;
      boolean write = WRITES.contains(request.getMethod());
      boolean access = method.hasMethodAnnotation(AuditedAccess.class);
      if (!write && !access) return;
      if (method.hasMethodAnnotation(NotAudited.class)) return;
      if (Boolean.TRUE.equals(request.getAttribute(AuditContext.RECORDED))) return;
      int status = response.getStatus();
      boolean denied = status == 403;
      if (!denied && (status < 200 || status >= 300)) return;

      String pattern = (String) request.getAttribute(HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE);
      if (pattern == null) return;
      if (pattern.startsWith(WebConfig.API_PREFIX)) pattern = pattern.substring(WebConfig.API_PREFIX.length());
      @SuppressWarnings("unchecked")
      Map<String, String> vars =
          (Map<String, String>) request.getAttribute(HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE);

      Entry e = describe(request.getMethod(), pattern, vars, access);
      Map<String, Object> after = new LinkedHashMap<>();
      Operation op = method.getMethodAnnotation(Operation.class);
      if (op != null && !op.summary().isBlank()) after.put("summary", op.summary());
      after.put("request", request.getMethod() + " " + pattern);
      after.put("status", status);
      if (denied) after.put("denied", true);
      if (vars != null && !vars.isEmpty()) after.put("pathVariables", vars);
      Object name = request.getAttribute(AuditContext.NAME);
      if (name == null && request instanceof MultipartHttpServletRequest multipart) {
        name = multipart.getFileMap().values().stream()
            .map(f -> f.getOriginalFilename()).filter(n -> n != null && !n.isBlank())
            .findFirst().orElse(null);
      }
      if (name != null) after.put("name", name);
      Object targetId = request.getAttribute(AuditContext.TARGET_ID);

      AuditLogService service = auditLogService.getIfAvailable();
      if (service == null) return;
      service.recordRequest(
          denied ? e.action() + ".denied" : e.action(),
          e.targetType(),
          targetId != null ? targetId.toString() : e.targetId(),
          after);
    } catch (Exception failure) {
      // Never break the response over its audit entry; but say so loudly.
      log.error("Could not write the audit entry for {} {}: {}",
          request.getMethod(), request.getRequestURI(), failure.getMessage(), failure);
    }
  }

  record Entry(String action, String targetType, String targetId) {}

  /**
   * "PUT /files/{fileId}/favourite" → action {@code file.favourite.set}, type {@code file}, id the
   * fileId. The verb follows the method: POST create, PUT set, PATCH update, DELETE delete, and
   * {@code download} for an audited read.
   */
  static Entry describe(String method, String pattern, Map<String, String> vars, boolean access) {
    List<String> literals = new ArrayList<>();
    String firstVar = null;
    for (String seg : pattern.split("/")) {
      if (seg.isBlank()) continue;
      if (seg.startsWith("{")) {
        if (firstVar == null) firstVar = seg.substring(1, seg.length() - 1);
      } else {
        literals.add(seg);
      }
    }
    if (literals.isEmpty()) literals.add("api");
    String head = literals.get(0);
    String type = TYPE_NAMES.getOrDefault(head, singular(head));
    // "/monitor/networks/..." names its resource second.
    List<String> rest = new ArrayList<>(literals.subList(1, literals.size()));
    if (head.equals("monitor") && !rest.isEmpty()) rest.remove(0);
    if (head.equals("system") && !rest.isEmpty() && rest.get(0).equals("settings")) rest.remove(0);
    String verb =
        access
            ? "download"
            : switch (method) {
              case "POST" -> "create";
              case "PUT" -> "set";
              case "PATCH" -> "update";
              case "DELETE" -> "delete";
              default -> method.toLowerCase(Locale.ROOT);
            };
    StringBuilder action = new StringBuilder(type);
    for (String r : rest) action.append('.').append(r);
    action.append('.').append(verb);
    String targetId = firstVar != null && vars != null ? vars.get(firstVar) : null;
    // "/conversations/{fileId}/export": the thing acted on is the capture, so it groups and is
    // named with the capture's other entries.
    String targetType = "fileId".equals(firstVar) ? "file" : type;
    return new Entry(action.toString(), targetType, targetId);
  }

  /** "files" → "file", "node-roles" → "node-role", "ip-org-rules" → "ip-org-rule". */
  static String singular(String plural) {
    if (plural.endsWith("ies")) return plural.substring(0, plural.length() - 3) + "y";
    if (plural.endsWith("ses")) return plural.substring(0, plural.length() - 2);
    if (plural.endsWith("s") && !plural.endsWith("ss")) return plural.substring(0, plural.length() - 1);
    return plural;
  }
}
