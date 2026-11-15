package com.tracepcap.monitor.dto;

import java.util.List;
import lombok.Builder;
import lombok.Value;

/**
 * Two private MACs that look like one device (#918 slice 4b): one stopped before the other began,
 * and they share what a device keeps when its MAC changes. A suggestion only; nothing is linked
 * until an analyst says so.
 */
@Value
@Builder
public class DeviceLinkSuggestionDto {
  /** The earlier MAC, and the snapshots it was seen in (1 = the first). */
  String macA;
  String nameA;
  int firstSnapshotA;
  int lastSnapshotA;
  /** The later MAC. */
  String macB;
  String nameB;
  int firstSnapshotB;
  int lastSnapshotB;
  List<Evidence> evidence;

  /** One reason they look like one device: strong, medium or weak. */
  @Value
  @Builder
  public static class Evidence {
    String strength;
    String what;
    String detail;
  }
}
