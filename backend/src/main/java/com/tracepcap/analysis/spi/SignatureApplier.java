package com.tracepcap.analysis.spi;

import com.tracepcap.analysis.service.PcapParserService;
import java.util.List;
import java.util.Map;

/**
 * Port for applying custom detection signatures during the analysis pipeline.
 *
 * <p>Defined in {@code analysis} (the ingest core) and implemented by the {@code signatures} feature
 * module, so the pipeline depends on this abstraction rather than on the concrete implementation.
 */
public interface SignatureApplier {

  /**
   * Evaluates all configured rules against each conversation and appends matched rule names to the
   * conversation's custom-signatures list, in place.
   */
  void applySignatures(List<PcapParserService.ConversationInfo> conversations);

  /**
   * Returns a map of IP address → custom device type for IPs involved in conversations matched by a
   * rule carrying a {@code device_type}. Call after {@link #applySignatures}.
   */
  Map<String, String> getDeviceTypeOverrides(List<PcapParserService.ConversationInfo> conversations);
}
