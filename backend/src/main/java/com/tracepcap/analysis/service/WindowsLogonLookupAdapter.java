package com.tracepcap.analysis.service;

import com.tracepcap.analysis.repository.WindowsLogonRepository;
import com.tracepcap.analysis.spi.WindowsLogonLookup;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@RequiredArgsConstructor
public class WindowsLogonLookupAdapter implements WindowsLogonLookup {

  private final WindowsLogonRepository repository;

  @Override
  @Transactional(readOnly = true)
  public List<WindowsLogon> logonsFor(UUID fileId, String ip) {
    return repository.findByFileIdAndIpOrderByFirstSeenAscIdAsc(fileId, ip).stream()
        .map(
            e ->
                new WindowsLogon(
                    e.getUsername(),
                    e.getSource(),
                    e.getDirectoryEntry(),
                    e.getFolder(),
                    e.getFolderKind(),
                    e.getDomain(),
                    e.getFirstSeen(),
                    e.getLastSeen(),
                    e.getSeenCount(),
                    "CUSTOM".equals(e.getFolderKind())))
        .toList();
  }
}
