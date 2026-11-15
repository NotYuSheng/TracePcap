package com.tracepcap.analysis.service;

import com.tracepcap.analysis.dto.occupancy.DeviceMoveDto;
import com.tracepcap.analysis.dto.occupancy.HostOccupancyResponse;
import com.tracepcap.analysis.dto.segments.NetworkSegmentsResponse;
import com.tracepcap.analysis.spi.CaptureNetworkLookup;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
class CaptureNetworkLookupImpl implements CaptureNetworkLookup {

  private final NetworkSegmentService segments;
  private final HostOccupancyService occupancies;

  @Override
  public NetworkSegmentsResponse networks(UUID fileId) {
    return segments.segments(fileId);
  }

  @Override
  public List<HostOccupancyResponse.ReusedAddress> sharedAddresses(UUID fileId) {
    return occupancies.listForFile(fileId);
  }

  @Override
  public List<DeviceMoveDto> moves(UUID fileId) {
    return occupancies.moves(fileId);
  }
}
