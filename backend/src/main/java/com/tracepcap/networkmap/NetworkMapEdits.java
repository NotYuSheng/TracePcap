package com.tracepcap.networkmap;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.util.Map;

/**
 * An analyst's edits to a capture's network map, stored as one document.
 *
 * @param placements device (graph node id) → the group it was moved to (a group id of the map)
 */
public record NetworkMapEdits(
    @NotNull @Size(max = 20000) Map<@Size(min = 1, max = 300) String, @Size(min = 1, max = 300) String> placements) {

  public static NetworkMapEdits empty() {
    return new NetworkMapEdits(Map.of());
  }
}
