package com.tracepcap.file.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * When a capture is deleted. {@code keepForever}: never. Else {@code expiresAt} (epoch ms, at most
 * a year away) keeps it until then, and null puts it back on the retention window.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ExpiryRequest {
  private boolean keepForever;
  private Long expiresAt;
}
