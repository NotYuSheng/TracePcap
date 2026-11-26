package com.tracepcap.analysis.spi;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

/**
 * What one host did to another over SMB and RPC (#1266), from Suricata's records: the shares it
 * connected to, the files and pipes it opened, the files it copied and the RPC calls it made. For
 * the knowledge layer's lateral-movement findings.
 */
public interface RemoteOperationLookup {

  /**
   * One kind of operation on a conversation, grouped.
   *
   * @param kind {@code share} (connected to a share), {@code open} (opened a file or pipe), {@code
   *     write} / {@code read} (a file copied to / from the server), or {@code rpc} (an RPC call)
   * @param share the share as connected, "\\host\ADMIN$", when known
   * @param interfaceName the RPC interface's short name ("svcctl"), null when not a known one
   * @param operation the RPC operation's name ("CreateServiceW"), null when not a named one
   * @param status SMB's error ("STATUS_ACCESS_DENIED"); null when it succeeded
   */
  record RemoteOperationFacts(
      UUID conversationId,
      LocalDateTime firstTime,
      String client,
      String server,
      String kind,
      String share,
      String path,
      String interfaceUuid,
      String interfaceName,
      Integer opnum,
      String operation,
      Long bytes,
      String status,
      int count) {}

  /** A capture's operations, oldest first. */
  List<RemoteOperationFacts> forFile(UUID fileId);
}
