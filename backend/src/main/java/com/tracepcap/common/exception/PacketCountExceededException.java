package com.tracepcap.common.exception;

import lombok.Getter;

/**
 * Thrown when an uploaded capture holds more packets than this instance is provisioned to analyse.
 *
 * <p>The limit is a deliberate provisioning contract, not a hard technical ceiling: the packet
 * count (measured by {@code capinfos} at upload) is the dominant driver of database row counts, and
 * therefore of the parallel-query shared-memory Postgres needs. Raising it means also raising the
 * Postgres {@code shm_size}/{@code work_mem} budget — see {@code .env.example} and the ops docs.
 */
@Getter
public class PacketCountExceededException extends RuntimeException {

  /** Sentinel for {@link #packetCount} when the count could not be verified (capinfos failed). */
  public static final long UNKNOWN_COUNT = -1L;

  private final long packetCount;
  private final long maxPackets;

  public PacketCountExceededException(long packetCount, long maxPackets) {
    super(
        String.format(
            "This capture has %,d packets, but this instance is provisioned for %,d. "
                + "Ask an administrator to raise MAX_UPLOAD_PACKETS (and the matching Postgres "
                + "shared-memory settings) to analyse larger captures.",
            packetCount, maxPackets));
    this.packetCount = packetCount;
    this.maxPackets = maxPackets;
  }

  /**
   * The count could not be determined and the file is too large to accept unverified.
   *
   * @param maxPackets the provisioned limit, named in the message
   * @param retryable whether retrying could plausibly succeed. {@code true} for a direct upload (a
   *     transient capinfos failure may clear on retry); {@code false} for a merge, where the merged
   *     file is deterministic so capinfos will fail identically every time — retrying is a dead end,
   *     so the message points at the config knob instead.
   */
  public PacketCountExceededException(long maxPackets, boolean retryable) {
    super(
        String.format(
            "This capture's packet count could not be verified, and it is too large to accept "
                + "without a count against the provisioned limit of %,d packets. %s",
            maxPackets,
            retryable
                ? "Retry the upload, or ask an administrator to raise MAX_UPLOAD_PACKETS (and the "
                    + "matching Postgres shared-memory settings), or MAX_UPLOAD_PACKETS_VERIFY_FRACTION."
                : "Ask an administrator to raise MAX_UPLOAD_PACKETS (and the matching Postgres "
                    + "shared-memory settings), or MAX_UPLOAD_PACKETS_VERIFY_FRACTION."));
    this.packetCount = UNKNOWN_COUNT;
    this.maxPackets = maxPackets;
  }
}
