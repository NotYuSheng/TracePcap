package com.tracepcap.analysis.dto.occupancy;

import java.time.LocalDateTime;

/**
 * A device that moved to another address within a capture: the same MAC on one address, then
 * another. {@code fromKey}/{@code toKey} are its device keys there (the bare IP, or ip@start /
 * ip~network when the address was shared), which is what the network graph's nodes are keyed by.
 */
public record DeviceMoveDto(
    String mac,
    String fromIp,
    String fromKey,
    String fromHostname,
    LocalDateTime left,
    String toIp,
    String toKey,
    String toHostname,
    LocalDateTime arrived,
    /** What showed the new address: "DHCP lease" or "ARP". */
    String evidence) {}
