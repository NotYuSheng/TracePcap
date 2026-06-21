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
   * Evaluates all configured rules against each conversation in a single pass: appends matched rule
   * names to each conversation's custom-signatures list (in place), and returns a map of IP address
   * → custom device type for IPs matched by a rule carrying a {@code device_type}.
   *
   * <p>Combining both outputs into one call avoids re-reading and re-parsing the rules file, and
   * removes the ordering dependency the previous two-method contract had (the device-type overrides
   * are derived from the matches applied here).
   *
   * @return device-type overrides keyed by IP; empty if no rules carry a {@code device_type}
   */
  Map<String, String> applySignatures(List<PcapParserService.ConversationInfo> conversations);
}
