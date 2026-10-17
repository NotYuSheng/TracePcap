package com.tracepcap.common.exception;

import com.fasterxml.jackson.core.exc.StreamConstraintsException;
import com.tracepcap.common.dto.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

/** Global exception handler for REST controllers */
@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

  private static final long BYTES_PER_MB = 1024L * 1024L;

  // Mirrors backend/docker-entrypoint.sh's JACKSON_MAX_STRING_MB derivation exactly
  // (EFFECTIVE_MEM_MB / 40, clamped to [8, 256]) so a recommended APP_MEMORY_MB actually produces
  // a cap that fits the request that just failed. Keep these two in sync if that formula changes.
  private static final int JACKSON_CAP_DIVISOR = 40;
  private static final int JACKSON_CAP_MAX_MB = 256;

  // Jackson's own message shape (StreamConstraintsException), e.g.
  // "String length (20054016) exceeds the maximum length (20000000)". Stable across the
  // jackson-core versions this app has used, but not a public API — a future upgrade could
  // reword it, in which case this handler simply falls back to the generic message below.
  private static final Pattern STRING_LENGTH_EXCEEDED =
      Pattern.compile("String length \\((\\d+)\\) exceeds the maximum length \\((\\d+)\\)");

  @Value("${tracepcap.jackson.max-string-length}")
  private long currentMaxStringLength;

  @ExceptionHandler(ResourceNotFoundException.class)
  public ResponseEntity<ErrorResponse> handleResourceNotFoundException(
      ResourceNotFoundException ex, HttpServletRequest request) {
    log.error("Resource not found: {}", ex.getMessage());

    ErrorResponse error =
        ErrorResponse.builder()
            .timestamp(LocalDateTime.now())
            .status(HttpStatus.NOT_FOUND.value())
            .error(HttpStatus.NOT_FOUND.getReasonPhrase())
            .message(ex.getMessage())
            .path(request.getRequestURI())
            .build();

    return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
  }

  @ExceptionHandler(DuplicateFileException.class)
  public ResponseEntity<ErrorResponse> handleDuplicateFileException(
      DuplicateFileException ex, HttpServletRequest request) {
    log.warn("Duplicate file upload rejected: existing file ID {}", ex.getExistingFileId());

    ErrorResponse error =
        ErrorResponse.builder()
            .timestamp(LocalDateTime.now())
            .status(HttpStatus.CONFLICT.value())
            .error("Conflict")
            .message(ex.getMessage())
            .path(request.getRequestURI())
            .existingFileId(ex.getExistingFileId().toString())
            .build();

    return ResponseEntity.status(HttpStatus.CONFLICT).body(error);
  }

  @ExceptionHandler(InvalidFileException.class)
  public ResponseEntity<ErrorResponse> handleInvalidFileException(
      InvalidFileException ex, HttpServletRequest request) {
    log.error("Invalid file: {}", ex.getMessage());

    ErrorResponse error =
        ErrorResponse.builder()
            .timestamp(LocalDateTime.now())
            .status(HttpStatus.UNPROCESSABLE_ENTITY.value())
            .error("Unprocessable Entity")
            .message(ex.getMessage())
            .path(request.getRequestURI())
            .build();

    return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body(error);
  }

  @ExceptionHandler(InsufficientEvidenceException.class)
  public ResponseEntity<ErrorResponse> handleInsufficientEvidenceException(
      InsufficientEvidenceException ex, HttpServletRequest request) {
    log.warn("Insufficient evidence: {}", ex.getMessage());

    ErrorResponse error =
        ErrorResponse.builder()
            .timestamp(LocalDateTime.now())
            .status(HttpStatus.UNPROCESSABLE_ENTITY.value())
            .error("Unprocessable Entity")
            .message(ex.getMessage())
            .path(request.getRequestURI())
            .build();

    return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body(error);
  }

  @ExceptionHandler(StorageException.class)
  public ResponseEntity<ErrorResponse> handleStorageException(
      StorageException ex, HttpServletRequest request) {
    log.error("Storage error: {}", ex.getMessage(), ex);

    ErrorResponse error =
        ErrorResponse.builder()
            .timestamp(LocalDateTime.now())
            .status(HttpStatus.SERVICE_UNAVAILABLE.value())
            .error("Service Unavailable")
            .message(ex.getMessage())
            .path(request.getRequestURI())
            .build();

    return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(error);
  }

  @ExceptionHandler(ContextLengthExceededException.class)
  public ResponseEntity<ErrorResponse> handleContextLengthExceededException(
      ContextLengthExceededException ex, HttpServletRequest request) {
    log.error("LLM context length exceeded: {}", ex.getMessage());

    ErrorResponse error =
        ErrorResponse.builder()
            .timestamp(LocalDateTime.now())
            .status(HttpStatus.UNPROCESSABLE_ENTITY.value())
            .error("Unprocessable Entity")
            .message(ex.getMessage())
            .path(request.getRequestURI())
            .errorCode("CONTEXT_LENGTH_EXCEEDED")
            .promptText(ex.getPrompt())
            .promptTokens(ex.getPromptTokens())
            .contextLength(ex.getContextLength())
            .build();

    return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body(error);
  }

  @ExceptionHandler(LlmException.class)
  public ResponseEntity<ErrorResponse> handleLlmException(
      LlmException ex, HttpServletRequest request) {
    log.error("LLM service error: {}", ex.getMessage());

    ErrorResponse error =
        ErrorResponse.builder()
            .timestamp(LocalDateTime.now())
            .status(HttpStatus.BAD_GATEWAY.value())
            .error("Bad Gateway")
            .message(ex.getMessage())
            .path(request.getRequestURI())
            .errorCode(ex.getErrorCode().name())
            .build();

    return ResponseEntity.status(HttpStatus.BAD_GATEWAY).body(error);
  }

  @ExceptionHandler(IllegalArgumentException.class)
  public ResponseEntity<ErrorResponse> handleIllegalArgumentException(
      IllegalArgumentException ex, HttpServletRequest request) {
    log.warn("Bad request: {}", ex.getMessage());

    ErrorResponse error =
        ErrorResponse.builder()
            .timestamp(LocalDateTime.now())
            .status(HttpStatus.BAD_REQUEST.value())
            .error("Bad Request")
            .message(ex.getMessage())
            .path(request.getRequestURI())
            .build();

    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
  }

  @ExceptionHandler(MaxUploadSizeExceededException.class)
  public ResponseEntity<ErrorResponse> handleMaxUploadSizeExceededException(
      MaxUploadSizeExceededException ex, HttpServletRequest request) {
    log.error("File too large: {}", ex.getMessage());

    ErrorResponse error =
        ErrorResponse.builder()
            .timestamp(LocalDateTime.now())
            .status(HttpStatus.PAYLOAD_TOO_LARGE.value())
            .error("Payload Too Large")
            .message("File size exceeds maximum allowed size")
            .path(request.getRequestURI())
            .build();

    return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE).body(error);
  }

  @ExceptionHandler(HttpMessageNotReadableException.class)
  public ResponseEntity<ErrorResponse> handleHttpMessageNotReadable(
      HttpMessageNotReadableException ex, HttpServletRequest request) {
    Throwable cause = ex.getMostSpecificCause();
    Matcher matcher =
        cause instanceof StreamConstraintsException
            ? STRING_LENGTH_EXCEEDED.matcher(cause.getMessage() == null ? "" : cause.getMessage())
            : null;

    if (matcher != null && matcher.find()) {
      log.warn("Request field exceeded the JSON string length cap: {}", cause.getMessage());
      return stringTooLargeResponse(Long.parseLong(matcher.group(1)), request);
    }

    log.warn("Malformed request body: {}", ex.getMessage());
    ErrorResponse error =
        ErrorResponse.builder()
            .timestamp(LocalDateTime.now())
            .status(HttpStatus.BAD_REQUEST.value())
            .error(HttpStatus.BAD_REQUEST.getReasonPhrase())
            .message("Malformed request body")
            .path(request.getRequestURI())
            .build();
    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
  }

  /**
   * Builds the actionable response for a JSON string that exceeded {@link
   * #currentMaxStringLength}: how big it was, and — unless it's past the derivation's own hard
   * ceiling — what {@code APP_MEMORY_MB} would need to be for a request this size to fit.
   */
  private ResponseEntity<ErrorResponse> stringTooLargeResponse(
      long attemptedBytes, HttpServletRequest request) {
    long attemptedMb = ceilDiv(attemptedBytes, BYTES_PER_MB);
    long currentCapMb = currentMaxStringLength / BYTES_PER_MB;

    Integer recommendedAppMemoryMb = null;
    String message;
    if (attemptedMb > JACKSON_CAP_MAX_MB) {
      message =
          String.format(
              "Request field is %d MB, past the %d MB maximum this deployment supports "
                  + "regardless of memory settings. Reduce what's being sent (e.g. a "
                  + "lower-resolution diagram capture) rather than raising APP_MEMORY_MB.",
              attemptedMb, JACKSON_CAP_MAX_MB);
    } else {
      // +10% headroom so the same request doesn't land exactly on the new boundary, then round up
      // to a clean step — operators think in round APP_MEMORY_MB numbers.
      long withHeadroomMb = ceilDiv(attemptedMb * 11, 10);
      long neededBudgetMb = withHeadroomMb * JACKSON_CAP_DIVISOR;
      recommendedAppMemoryMb = (int) (ceilDiv(neededBudgetMb, 256) * 256);
      message =
          String.format(
              "Request field is %d MB, over this deployment's current %d MB limit "
                  + "(derived from APP_MEMORY_MB). Raise APP_MEMORY_MB to at least %d in "
                  + "the backend's environment and restart it.",
              attemptedMb, currentCapMb, recommendedAppMemoryMb);
    }

    ErrorResponse error =
        ErrorResponse.builder()
            .timestamp(LocalDateTime.now())
            .status(HttpStatus.PAYLOAD_TOO_LARGE.value())
            .error(HttpStatus.PAYLOAD_TOO_LARGE.getReasonPhrase())
            .message(message)
            .path(request.getRequestURI())
            .errorCode("PAYLOAD_STRING_TOO_LARGE")
            .attemptedSizeMb((int) attemptedMb)
            .recommendedAppMemoryMb(recommendedAppMemoryMb)
            .build();
    return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE).body(error);
  }

  private static long ceilDiv(long numerator, long denominator) {
    return (numerator + denominator - 1) / denominator;
  }

  @ExceptionHandler(MethodArgumentNotValidException.class)
  public ResponseEntity<ErrorResponse> handleMethodArgumentNotValid(
      MethodArgumentNotValidException ex, HttpServletRequest request) {
    Map<String, String> fieldErrors = new LinkedHashMap<>();
    ex.getBindingResult()
        .getFieldErrors()
        .forEach(
            fe ->
                fieldErrors.putIfAbsent(
                    fe.getField(),
                    fe.getDefaultMessage() != null ? fe.getDefaultMessage() : "is invalid"));
    log.warn("Validation failed for request body: {}", fieldErrors);

    ErrorResponse error =
        ErrorResponse.builder()
            .timestamp(LocalDateTime.now())
            .status(HttpStatus.BAD_REQUEST.value())
            .error(HttpStatus.BAD_REQUEST.getReasonPhrase())
            .message("Validation failed")
            .path(request.getRequestURI())
            .validationErrors(fieldErrors)
            .build();

    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
  }

  @ExceptionHandler(ConstraintViolationException.class)
  public ResponseEntity<ErrorResponse> handleConstraintViolation(
      ConstraintViolationException ex, HttpServletRequest request) {
    Map<String, String> fieldErrors = new LinkedHashMap<>();
    for (ConstraintViolation<?> v : ex.getConstraintViolations()) {
      String path = v.getPropertyPath().toString();
      // Property path is like "methodName.paramName"; keep the trailing parameter name.
      String field = path.contains(".") ? path.substring(path.lastIndexOf('.') + 1) : path;
      fieldErrors.putIfAbsent(field, v.getMessage());
    }
    log.warn("Constraint violation on request parameters: {}", fieldErrors);

    ErrorResponse error =
        ErrorResponse.builder()
            .timestamp(LocalDateTime.now())
            .status(HttpStatus.BAD_REQUEST.value())
            .error(HttpStatus.BAD_REQUEST.getReasonPhrase())
            .message("Validation failed")
            .path(request.getRequestURI())
            .validationErrors(fieldErrors)
            .build();

    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
  }

  @ExceptionHandler(NoResourceFoundException.class)
  public ResponseEntity<ErrorResponse> handleNoResourceFound(
      NoResourceFoundException ex, HttpServletRequest request) {
    log.warn("No resource for path: {}", request.getRequestURI());

    ErrorResponse error =
        ErrorResponse.builder()
            .timestamp(LocalDateTime.now())
            .status(HttpStatus.NOT_FOUND.value())
            .error(HttpStatus.NOT_FOUND.getReasonPhrase())
            .message("Resource not found")
            .path(request.getRequestURI())
            .build();

    return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
  }

  @ExceptionHandler(Exception.class)
  public ResponseEntity<ErrorResponse> handleGlobalException(
      Exception ex, HttpServletRequest request) {
    log.error("Unexpected error: {}", ex.getMessage(), ex);

    ErrorResponse error =
        ErrorResponse.builder()
            .timestamp(LocalDateTime.now())
            .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
            .error("Internal Server Error")
            .message("An unexpected error occurred")
            .path(request.getRequestURI())
            .build();

    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
  }
}
