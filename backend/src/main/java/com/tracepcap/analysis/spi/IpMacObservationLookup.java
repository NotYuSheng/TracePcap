package com.tracepcap.analysis.spi;

import java.util.List;
import java.util.UUID;

/**
 * Read port for the distinct MACs observed per IP in a file (#461, ported in #512 slice 6b).
 *
 * <p>More than one MAC for an IP means two devices claimed the same address in this capture —
 * overlapping networks, or an ARP conflict. The port answers that question directly rather than
 * handing back raw observation rows for each caller to group itself.
 */
public interface IpMacObservationLookup {

  /** The MACs seen claiming one IP. Both fields are non-null; {@code macs} is never empty. */
  record IpMacs(String ip, List<String> macs) {}

  /**
   * Every IP observed in the file with the MACs that claimed it, grouped and in first-seen order.
   * Never contains null elements.
   */
  List<IpMacs> ipMacObservations(UUID fileId);

  /** As {@link #ipMacObservations}, for one IP only: the MACs that claimed it (#469). */
  List<IpMacs> ipMacObservationsForIp(UUID fileId, String ip);

  /**
   * As {@link #ipMacObservations}, for only the IPs this MAC claimed, each with all its MACs (#469).
   * The MAC is matched case-insensitively.
   */
  List<IpMacs> ipMacObservationsForMac(UUID fileId, String mac);
}
