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
}
