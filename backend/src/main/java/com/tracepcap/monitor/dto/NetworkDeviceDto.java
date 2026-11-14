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
  /** The MAC it was last seen with. */
  String mac;
  /** Every MAC it was seen with: more than one when an analyst linked them as one device. */
  List<String> macs;
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
  /** The analyst's same / not-the-same decisions about its MACs. */
  List<Link> links;

  /** An address it used, from the first to the last snapshot it used it in (1 = the first snapshot). */
  @Value
  @Builder
  public static class Address {
    String ip;
    int firstSnapshot;
    int lastSnapshot;
  }

  /** An analyst's decision about two MACs: {@code decision} is same or not_same. */
  @Value
  @Builder
  public static class Link {
    Long id;
    String macA;
    String macB;
    String decision;
    String reason;
    String actor;
    java.time.LocalDateTime createdAt;
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
