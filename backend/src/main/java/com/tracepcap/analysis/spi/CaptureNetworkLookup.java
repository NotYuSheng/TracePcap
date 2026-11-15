package com.tracepcap.analysis.spi;

import com.tracepcap.analysis.dto.occupancy.DeviceMoveDto;
import com.tracepcap.analysis.dto.occupancy.HostOccupancyResponse;
import com.tracepcap.analysis.dto.segments.NetworkSegmentsResponse;
import java.util.List;
import java.util.UUID;

/**
 * Who was where in a capture, for modules outside analysis (the report): its networks from DHCP,
 * the addresses more than one device held in turn, and the devices that moved address.
 */
public interface CaptureNetworkLookup {

  /** Its networks, with their clients and the clients nobody answered. */
  NetworkSegmentsResponse networks(UUID fileId);

  /** Every address more than one device held, each device with its stretch. */
  List<HostOccupancyResponse.ReusedAddress> sharedAddresses(UUID fileId);

  /** Devices seen on one address, then another. */
  List<DeviceMoveDto> moves(UUID fileId);
}
