package com.tracepcap.common.exception;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.core.exc.StreamConstraintsException;
import com.tracepcap.common.dto.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

/**
 * Error-path matrix for {@link GlobalExceptionHandler}. The handler is a pure exception → {@link
 * ErrorResponse} mapping, so each branch is asserted directly (status code, reason phrase, error
 * code, and the common envelope fields) without a Spring context. The validation branches
 * (MethodArgumentNotValid / ConstraintViolation) are exercised end-to-end in the integration test,
 * where they are naturally thrown by the MVC stack.
 */
class GlobalExceptionHandlerTest {

  private static final GlobalExceptionHandler HANDLER = new GlobalExceptionHandler();
  private static final String PATH = "/api/v1/some/resource";

  // Matches the default derived cap (APP_MEMORY_MB=2048 -> 51MB), same value application.yml
  // falls back to when docker-entrypoint.sh isn't in the picture.
  private static final long DEFAULT_MAX_STRING_LENGTH = 53_477_376L;

  static {
    ReflectionTestUtils.setField(HANDLER, "currentMaxStringLength", DEFAULT_MAX_STRING_LENGTH);
  }

  private static HttpMessageNotReadableException stringLengthExceeded(long attemptedBytes) {
    return new HttpMessageNotReadableException(
        "JSON parse error: String length (" + attemptedBytes + ") exceeds the maximum length ("
            + DEFAULT_MAX_STRING_LENGTH + ")",
        new StreamConstraintsException(
            "String length (" + attemptedBytes + ") exceeds the maximum length ("
                + DEFAULT_MAX_STRING_LENGTH + ")"),
        null);
  }

  private static HttpServletRequest request() {
    MockHttpServletRequest req = new MockHttpServletRequest();
    req.setRequestURI(PATH);
    return req;
  }

  /** One row of the matrix: an exception mapping plus its expected status/reason/error code. */
  private record Case(
      String name,
      int expectedStatus,
      String expectedError,
      String expectedErrorCode,
      Function<HttpServletRequest, ResponseEntity<ErrorResponse>> invoke) {
    @Override
    public String toString() {
      return name;
    }
  }

  private static Stream<Case> cases() {
    return Stream.of(
        new Case(
            "ResourceNotFound -> 404",
            404,
            "Not Found",
            null,
            req -> HANDLER.handleResourceNotFoundException(new ResourceNotFoundException("nope"), req)),
        new Case(
            "DuplicateFile -> 409",
            409,
            "Conflict",
            null,
            req ->
                HANDLER.handleDuplicateFileException(
                    new DuplicateFileException(UUID.randomUUID()), req)),
        new Case(
            "InvalidFile -> 422",
            422,
            "Unprocessable Entity",
            null,
            req -> HANDLER.handleInvalidFileException(new InvalidFileException("bad"), req)),
        new Case(
            "Storage -> 503",
            503,
            "Service Unavailable",
            null,
            req -> HANDLER.handleStorageException(new StorageException("minio down"), req)),
        new Case(
            "ContextLengthExceeded -> 422",
            422,
            "Unprocessable Entity",
            "CONTEXT_LENGTH_EXCEEDED",
            req ->
                HANDLER.handleContextLengthExceededException(
                    new ContextLengthExceededException(9000, 8000, "prompt"), req)),
        new Case(
            "Llm -> 502",
            502,
            "Bad Gateway",
            "LLM_UNREACHABLE",
            req -> HANDLER.handleLlmException(new LlmException("unreachable"), req)),
        new Case(
            "IllegalArgument -> 400",
            400,
            "Bad Request",
            null,
            req ->
                HANDLER.handleIllegalArgumentException(new IllegalArgumentException("bad arg"), req)),
        new Case(
            "MaxUploadSizeExceeded -> 413",
            413,
            "Payload Too Large",
            null,
            req ->
                HANDLER.handleMaxUploadSizeExceededException(
                    new MaxUploadSizeExceededException(100L), req)),
        new Case(
            "NoResourceFound -> 404",
            404,
            "Not Found",
            null,
            req ->
                HANDLER.handleNoResourceFound(
                    new NoResourceFoundException(HttpMethod.GET, PATH), req)),
        new Case(
            "HttpMessageNotReadable, unrelated cause -> 400",
            400,
            "Bad Request",
            null,
            req ->
                HANDLER.handleHttpMessageNotReadable(
                    new HttpMessageNotReadableException("garbled JSON", (HttpInputMessage) null),
                    req)),
        new Case(
            "HttpMessageNotReadable, string-length cap -> 413",
            413,
            "Payload Too Large",
            "PAYLOAD_STRING_TOO_LARGE",
            req -> HANDLER.handleHttpMessageNotReadable(stringLengthExceeded(20_054_016L), req)),
        new Case(
            "Unhandled -> 500",
            500,
            "Internal Server Error",
            null,
            req -> HANDLER.handleGlobalException(new RuntimeException("boom"), req)));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("cases")
  void mapsExceptionToExpectedStatusAndEnvelope(Case c) {
    ResponseEntity<ErrorResponse> response = c.invoke().apply(request());

    assertThat(response.getStatusCode().value()).isEqualTo(c.expectedStatus());
    ErrorResponse body = response.getBody();
    assertThat(body).isNotNull();
    assertThat(body.getStatus()).isEqualTo(c.expectedStatus());
    assertThat(body.getError()).isEqualTo(c.expectedError());
    assertThat(body.getErrorCode()).isEqualTo(c.expectedErrorCode());
    // Common envelope contract: every error carries a timestamp, a message, and the request path.
    assertThat(body.getTimestamp()).isNotNull();
    assertThat(body.getMessage()).isNotBlank();
    assertThat(body.getPath()).isEqualTo(PATH);
  }

  @Test
  void duplicateFile_carriesExistingFileId() {
    UUID existing = UUID.randomUUID();
    ResponseEntity<ErrorResponse> response =
        HANDLER.handleDuplicateFileException(new DuplicateFileException(existing), request());

    assertThat(response.getBody()).isNotNull();
    assertThat(response.getBody().getExistingFileId()).isEqualTo(existing.toString());
  }

  @Test
  void contextLengthExceeded_carriesTokenDetails() {
    ResponseEntity<ErrorResponse> response =
        HANDLER.handleContextLengthExceededException(
            new ContextLengthExceededException(9000, 8000, "the prompt"), request());

    ErrorResponse body = response.getBody();
    assertThat(body).isNotNull();
    assertThat(body.getPromptTokens()).isEqualTo(9000);
    assertThat(body.getContextLength()).isEqualTo(8000);
    assertThat(body.getPromptText()).isEqualTo("the prompt");
  }

  @Test
  void stringTooLarge_recommendsAnAppMemoryMbThatWouldActuallyFit() {
    // The exact figures from the live report-download failure this handler exists for (#792):
    // a 20,054,016-char diagram string against the old fixed 20MB Jackson default.
    ResponseEntity<ErrorResponse> response =
        HANDLER.handleHttpMessageNotReadable(stringLengthExceeded(20_054_016L), request());

    ErrorResponse body = response.getBody();
    assertThat(body).isNotNull();
    assertThat(body.getErrorCode()).isEqualTo("PAYLOAD_STRING_TOO_LARGE");
    assertThat(body.getAttemptedSizeMb()).isEqualTo(20);
    // ceil(20 * 1.1) = 22MB needed cap -> 22 * 40 = 880MB budget -> rounded up to 1024MB.
    assertThat(body.getRecommendedAppMemoryMb()).isEqualTo(1024);
    assertThat(body.getMessage()).contains("APP_MEMORY_MB").contains("1024");

    // The recommendation must actually mirror docker-entrypoint.sh's derivation: at the
    // recommended budget, EFFECTIVE_MEM_MB / 40 must be >= the attempted size.
    long derivedCapMbAtRecommendation = body.getRecommendedAppMemoryMb() / 40;
    assertThat(derivedCapMbAtRecommendation).isGreaterThanOrEqualTo(body.getAttemptedSizeMb());
  }

  @Test
  void stringTooLarge_pastTheHardCeiling_recommendsNothing() {
    // 300MB is past JACKSON_CAP_MAX_MB (256) — no APP_MEMORY_MB raises the cap that high.
    long attemptedBytes = 300L * 1024 * 1024;
    ResponseEntity<ErrorResponse> response =
        HANDLER.handleHttpMessageNotReadable(stringLengthExceeded(attemptedBytes), request());

    ErrorResponse body = response.getBody();
    assertThat(body).isNotNull();
    assertThat(body.getErrorCode()).isEqualTo("PAYLOAD_STRING_TOO_LARGE");
    assertThat(body.getAttemptedSizeMb()).isEqualTo(300);
    assertThat(body.getRecommendedAppMemoryMb()).isNull();
    assertThat(body.getMessage()).contains("regardless of memory settings");
  }
}
