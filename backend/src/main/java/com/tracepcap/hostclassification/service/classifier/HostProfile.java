package com.tracepcap.hostclassification.service.classifier;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Per-host traffic profile accumulated from all conversations involving a host, used as input to the
 * device-classification signals. Not persisted.
 */
public class HostProfile {
  public long totalBytes = 0;
  public long totalPackets = 0;
  public int conversationCount = 0;
  public int initiatedCount = 0;
  public final Set<String> apps = new LinkedHashSet<>();
  public final Set<String> categories = new LinkedHashSet<>();
  public final Set<Integer> dstPorts = new LinkedHashSet<>();
  public final Set<Integer> receivedOnPorts = new LinkedHashSet<>();
  public final Set<String> peers = new LinkedHashSet<>();
}
