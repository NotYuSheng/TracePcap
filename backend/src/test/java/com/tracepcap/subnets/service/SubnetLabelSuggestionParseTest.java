package com.tracepcap.subnets.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.tracepcap.common.exception.InsufficientEvidenceException;
import org.junit.jupiter.api.Test;

/**
 * The LLM-response half of subnet label suggestion (#465). Local models wrap their JSON in
 * Markdown fences, add prose around it, or leave comments in it. This path accepts all of that and
 * regresses silently, since the suggestion just stops appearing.
 *
 * <p>{@code parse} reads no collaborators, so the service is built with nulls.
 */
class SubnetLabelSuggestionParseTest {

  private final SubnetLabelSuggestionService service =
      new SubnetLabelSuggestionService(null, null, null, null);

  @Test
  void plainJson() {
    var s = service.parse("{\"label\": \"Corporate workstations\", \"description\": \"Laptops.\"}");

    assertThat(s.label()).isEqualTo("Corporate workstations");
    assertThat(s.description()).isEqualTo("Laptops.");
  }

  @Test
  void fencedJsonBlockWithProseAroundIt() {
    String raw =
        """
        Here is my suggestion:
        ```json
        { "label": "  DMZ / public-facing services ", "description": " Web and mail. " }
        ```
        Let me know if you need more.
        """;

    var s = service.parse(raw);

    // Trimmed, and the prose and fences are ignored.
    assertThat(s.label()).isEqualTo("DMZ / public-facing services");
    assertThat(s.description()).isEqualTo("Web and mail.");
  }

  @Test
  void bareFenceAndComments() {
    String raw =
        """
        ```
        {
          // the model explains itself inline
          "label": "Server segment",
          "description": "Hosts serving DNS and HTTP."
        }
        ```
        """;

    assertThat(service.parse(raw).label()).isEqualTo("Server segment");
  }

  @Test
  void blankLabelWithADescription_keepsTheDescriptionAndNullsTheLabel() {
    var s = service.parse("{\"label\": \"   \", \"description\": \"Mixed devices, no clear role.\"}");

    assertThat(s.label()).isNull();
    assertThat(s.description()).isEqualTo("Mixed devices, no clear role.");
  }

  @Test
  void emptySuggestion_isInsufficientEvidence_notAParseFailure() {
    // A distinct exception: the API reports "not enough to go on", not a server error.
    assertThatThrownBy(() -> service.parse("{\"label\": \"\", \"description\": \"\"}"))
        .isInstanceOf(InsufficientEvidenceException.class);
    assertThatThrownBy(() -> service.parse("{}"))
        .isInstanceOf(InsufficientEvidenceException.class);
  }

  @Test
  void malformedJson_failsAsAParseError() {
    assertThatThrownBy(() -> service.parse("{\"label\": \"Unclosed"))
        .isInstanceOf(RuntimeException.class)
        .isNotInstanceOf(InsufficientEvidenceException.class)
        .hasMessageContaining("parse");
  }

  @Test
  void emptyResponse_fails() {
    assertThatThrownBy(() -> service.parse("   ")).isInstanceOf(RuntimeException.class);
    assertThatThrownBy(() -> service.parse(null)).isInstanceOf(RuntimeException.class);
  }
}
