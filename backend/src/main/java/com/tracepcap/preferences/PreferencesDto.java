package com.tracepcap.preferences;

import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.util.List;
import java.util.Map;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Personal preferences (#915 phase 2). Each field is null until set, meaning "use the app default".
 * {@link #shared} is read-only and tells the UI these are shared because login is off.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PreferencesDto {

  @Pattern(regexp = "system|light|dark")
  private String themeMode;

  /** The network diagram's node-label settings, as the frontend stores them. */
  private Map<String, Object> nodeLabelConfig;

  /** Visible conversation-table columns. */
  @Size(max = 50)
  private List<@Size(max = 64) String> conversationColumns;

  /** True when login is off and everyone using the install shares these. Ignored on write. */
  private boolean shared;
}
