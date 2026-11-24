package com.tracepcap.analysis.service;

import com.tracepcap.analysis.repository.KerberosExchangeRepository;
import com.tracepcap.analysis.spi.KerberosLookup;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@RequiredArgsConstructor
class KerberosLookupAdapter implements KerberosLookup {

  private final KerberosExchangeRepository repository;

  @Override
  @Transactional(readOnly = true)
  public List<KerberosFacts> forFile(UUID fileId) {
    return repository.findByFileIdOrderByFirstTimeAsc(fileId).stream()
        .map(k -> new KerberosFacts(k.getConversationId(), k.getFirstTime(), k.getClientIp(),
            k.getKdcIp(), k.getMsgType(), k.getAccount(), k.getService(), k.getRealm(),
            k.getErrorCode(), k.getEncryption(), k.isWeak(), k.getCount()))
        .toList();
  }
}
