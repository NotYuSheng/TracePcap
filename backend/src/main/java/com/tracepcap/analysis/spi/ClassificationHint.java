package com.tracepcap.analysis.spi;

/**
 * A weighted vote for a host's device type from something other than its own traffic (#926):
 * today, a detection rule's classification hint ("hosts matching rtsp_camera are probably a CCTV
 * Camera"). It joins the explainable vote like any other signal; it never overrides it, and a human
 * label still wins.
 *
 * @param source what cast it, shown in the evidence, e.g. the rule's name
 * @param deviceType the type it votes for
 * @param weight points added, 1 to 100
 */
public record ClassificationHint(String source, String deviceType, int weight) {}
