package com.tracepcap.analysis.service;

import com.tracepcap.analysis.repository.DhcpLeaseRepository;
import com.tracepcap.analysis.repository.RouterAdvertRepository;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * A capture's networks (#462), read from everything that tells them apart: its DHCP leases (v4 and
 * v6) and its IPv6 router advertisements (#1357). The one way in, so no reader sees half of them.
 */
@Component
@RequiredArgsConstructor
public class NetworkSegmentReader {

  private final DhcpLeaseRepository leases;
  private final RouterAdvertRepository adverts;

  @Transactional(readOnly = true)
  public NetworkSegments.Result of(UUID fileId) {
    return NetworkSegments.of(leases.findByFileId(fileId), adverts.findByFileId(fileId));
  }
}
