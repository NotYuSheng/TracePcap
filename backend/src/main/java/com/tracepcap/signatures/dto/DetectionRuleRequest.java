package com.tracepcap.signatures.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * A detection rule as the editor sends it (#925). Every match field is optional, but a rule needs
 * at least one match field or payload pattern; the service checks that, and that IPs, CIDRs, hex
 * and regexes are valid.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DetectionRuleRequest {

  @NotBlank
  @Size(max = 200)
  private String name;

  @Size(max = 2000)
  private String description;

  @NotBlank
  @Pattern(regexp = "low|medium|high|critical", message = "must be low, medium, high or critical")
  private String severity;

  @Builder.Default private boolean enabled = true;

  @Valid private Match match;

  @Size(max = 50)
  private List<@Valid PayloadPattern> payloadContains;

  @Size(max = 50)
  private List<@Valid RegexPattern> payloadRegex;

  /** Require every payload pattern to match, instead of any one. */
  private boolean matchAll;

  /**
   * Classification hint (#926): hosts matching this rule are probably this device type, e.g.
   * {@code IOT} or {@code CCTV Camera}. A weighted vote in device classification; optional.
   */
  @Size(max = 100)
  private String deviceType;

  /** The hint's weight, 1 to 100 (other signals add 5 to 35). Defaults to 40. */
  @jakarta.validation.constraints.Min(1)
  @jakarta.validation.constraints.Max(100)
  private Integer deviceTypeWeight;

  /** All optional; a rule fires when every field given matches. */
  @Data
  @Builder
  @NoArgsConstructor
  @AllArgsConstructor
  public static class Match {
    @Size(max = 64) private String ip;
    @Size(max = 64) private String cidr;
    private Integer srcPort;
    private Integer dstPort;
    @Size(max = 64) private String ja3;
    @Size(max = 255) private String hostname;
    @Size(max = 100) private String app;
    @Size(max = 32) private String protocol;
  }

  /** Exactly one of {@code ascii} or {@code hex}. */
  @Data
  @Builder
  @NoArgsConstructor
  @AllArgsConstructor
  public static class PayloadPattern {
    @Size(max = 1000) private String ascii;
    @Size(max = 2000) private String hex;
  }

  @Data
  @Builder
  @NoArgsConstructor
  @AllArgsConstructor
  public static class RegexPattern {
    @NotBlank @Size(max = 1000) private String pattern;
    private boolean caseInsensitive;
  }
}
