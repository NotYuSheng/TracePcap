package com.tracepcap.analysis.service;

import com.tracepcap.analysis.repository.RemoteOperationRepository;
import com.tracepcap.analysis.spi.RemoteOperationLookup;
import com.tracepcap.common.net.MsRpc;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@RequiredArgsConstructor
class RemoteOperationLookupAdapter implements RemoteOperationLookup {

  private final RemoteOperationRepository repository;

  @Override
  @Transactional(readOnly = true)
  public List<RemoteOperationFacts> forFile(UUID fileId) {
    return repository.findByFileIdOrderByFirstTimeAsc(fileId).stream()
        .map(o -> new RemoteOperationFacts(
            o.getConversationId(), o.getFirstTime(), o.getClientIp(), o.getServerIp(), o.getKind(),
            o.getShare(), o.getPath(), o.getInterfaceUuid(), MsRpc.interfaceName(o.getInterfaceUuid()),
            o.getOpnum(), MsRpc.operationName(o.getInterfaceUuid(), o.getOpnum()), o.getBytes(),
            o.getStatus(), o.getCount()))
        .toList();
  }
}
