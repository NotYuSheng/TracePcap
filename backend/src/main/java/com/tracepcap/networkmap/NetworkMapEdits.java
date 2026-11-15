package com.tracepcap.networkmap;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.util.List;
import java.util.Map;

/**
 * An analyst's edits to a capture's network map, stored as one document.
 *
 * @param placements device (graph node id) → the group it was moved to (a group id of the map)
 * @param groups the analyst's own groups, each inside a group of the map
 * @param names group id → the name the analyst gave it (any group, automatic or their own)
 * @param notes group id → the analyst's note on it
 */
public record NetworkMapEdits(
    @Size(max = 20000) Map<@Size(min = 1, max = 300) String, @Size(min = 1, max = 300) String> placements,
    @Size(max = 500) List<@Valid UserGroup> groups,
    @Size(max = 2000) Map<@Size(min = 1, max = 300) String, @Size(min = 1, max = 120) String> names,
    @Size(max = 2000) Map<@Size(min = 1, max = 300) String, @Size(max = 2000) String> notes) {

  /** A group the analyst made: shown as a box inside {@code parentId}'s, for devices to be moved into. */
  public record UserGroup(
      @NotBlank @Pattern(regexp = "user:[A-Za-z0-9-]{1,64}") String id,
      @NotBlank @Size(max = 120) String name,
      @NotBlank @Size(max = 300) String parentId) {}

  public NetworkMapEdits {
    placements = placements == null ? Map.of() : placements;
    groups = groups == null ? List.of() : groups;
    names = names == null ? Map.of() : names;
    notes = notes == null ? Map.of() : notes;
  }

  public static NetworkMapEdits empty() {
    return new NetworkMapEdits(Map.of(), List.of(), Map.of(), Map.of());
  }
}
