package com.tracepcap.insights.dto;

import lombok.Data;

/** Options controlling how an insight is generated. All fields are optional — defaults apply. */
@Data
public class GenerateInsightRequest {

  /**
   * Audience tone.
   * TECHNICAL  — MACs, IPs, protocol names verbatim (default)
   * EXECUTIVE  — plain English, no jargon
   * OT         — framed around operational / industrial impact
   */
  private String audience = "TECHNICAL";

  /**
   * Analytical focus.
   * SECURITY    — suspicious patterns, investigation leads (default)
   * OPERATIONAL — expected vs unexpected from a network ops perspective
   * COMPLIANCE  — deviations from baseline, reviewed vs unreviewed
   */
  private String focus = "SECURITY";
}
