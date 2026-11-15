package com.tracepcap.story.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * What to test. Any value left blank is the one in effect now (Settings, else the deployment), so
 * an empty body tests the current connection and a filled one tests a change before saving it.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class LlmTestRequest {
  private String baseUrl;
  private String apiKey;
  private String model;
}
