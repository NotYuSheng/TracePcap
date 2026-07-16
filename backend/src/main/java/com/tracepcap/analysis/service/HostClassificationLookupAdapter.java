package com.tracepcap.analysis.service;

import com.tracepcap.analysis.repository.HostClassificationRepository;
import com.tracepcap.analysis.spi.HostClassificationLookup;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/** Serves {@link HostClassificationLookup} from the analysis module's own repository. */
@Component
@RequiredArgsConstructor
public class HostClassificationLookupAdapter implements HostClassificationLookup {

  private final HostClassificationRepository repository;

  @Override
  public List<ClassifiedHost> classifiedHosts(UUID fileId) {
    return repository.findByFileId(fileId).stream()
        .map(
            e ->
                new ClassifiedHost(
                    e.getIp(),
                    e.getDeviceType(),
                    e.getConfidence(),
                    e.getWinnerScore(),
                    e.getRunnerUpType(),
                    e.getRunnerUpScore()))
        .toList();
  }
}
