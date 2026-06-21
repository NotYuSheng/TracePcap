package com.tracepcap.analysis.spi;

import com.tracepcap.analysis.entity.HostClassificationEntity;
import com.tracepcap.analysis.service.HostnameResolverService;
import com.tracepcap.analysis.service.PcapParserService;
import com.tracepcap.file.entity.FileEntity;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Port for classifying hosts (device type / role) from observed traffic during the analysis
 * pipeline.
 *
 * <p>Defined in {@code analysis} (the ingest core) and implemented by the {@code hostclassification}
 * feature module, so the pipeline depends on this abstraction rather than on the concrete
 * classification engine. Returns the core {@link HostClassificationEntity} records, which the
 * pipeline post-processes (e.g. service-log suspicions) and persists.
 */
public interface HostClassifier {

  List<HostClassificationEntity> classify(
      FileEntity file,
      List<PcapParserService.ConversationInfo> conversations,
      Map<String, Integer> hostTtls,
      Map<String, String> hostMacs,
      Map<String, String> deviceOverrides,
      Map<String, HostnameResolverService.ResolvedHostname> hostnames,
      Map<String, Set<String>> serviceRolesByIp);
}
