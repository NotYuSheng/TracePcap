package com.tracepcap.monitor.dto;

import java.util.List;
import java.util.UUID;
import lombok.Builder;
import lombok.Value;

/**
 * One device across a network's snapshots (#918 slice 4), recognised by its MAC: what it is, the
 * addresses it used, which snapshots it was seen in, its label, and anything irregular about it.
 */
@Value
@Builder
public class NetworkDeviceDto {
  String mac;
  /** Its hostname in the latest snapshot it was seen in, else its address there. */
  String name;
  String deviceType;
  String vendor;
  /** HARDWARE, PRIVATE (the device made the MAC up), VIRTUAL_MACHINE or CONTAINER. */
  String macKind;
  /** The analyst's label on it in the latest snapshot that has one. */
  String label;
  List<Address> addresses;
  /** The files (snapshots) it was seen in, in snapshot order. */
  List<UUID> seenInFileIds;
  /** Where to open it: the latest snapshot it was seen in, and its key there (ip, or ip@start). */
  UUID lastFileId;
  String lastKey;
  List<Flag> flags;

  /** An address it used, from the first to the last snapshot it used it in (1 = the first snapshot). */
  @Value
  @Builder
  public static class Address {
    String ip;
    int firstSnapshot;
    int lastSnapshot;
  }

  /** An irregularity: high (likely two machines), medium (worth knowing) or info. */
  @Value
  @Builder
  public static class Flag {
    String kind;
    String severity;
    String text;
  }
}
