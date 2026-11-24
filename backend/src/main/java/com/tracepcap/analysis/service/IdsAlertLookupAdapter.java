package com.tracepcap.analysis.service;

import com.tracepcap.analysis.entity.IdsAlertEntity;
import com.tracepcap.analysis.repository.IdsAlertRepository;
import com.tracepcap.analysis.spi.IdsAlertLookup;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@RequiredArgsConstructor
class IdsAlertLookupAdapter implements IdsAlertLookup {

  private final IdsAlertRepository repository;
  private final com.tracepcap.analysis.repository.SuricataAnomalyRepository anomalies;

  @Override
  @Transactional(readOnly = true)
  public List<AnomalyFacts> anomaliesFor(UUID conversationId) {
    return anomalies.findByConversationIdOrderByTimeAsc(conversationId).stream()
        .map(a -> new AnomalyFacts(a.getTime(), a.getSrcIp(), a.getDstIp(), a.getType(), a.getLayer(),
            a.getAppProto(), a.getEvent()))
        .toList();
  }

  @Override
  @Transactional(readOnly = true)
  public List<IdsAlertFacts> forConversation(UUID conversationId) {
    return repository.findByConversationIdOrderByAlertTimeAsc(conversationId).stream()
        .map(IdsAlertLookupAdapter::facts)
        .toList();
  }

  @Override
  @Transactional(readOnly = true)
  public List<IdsAlertFacts> forFile(UUID fileId) {
    return repository.findByFileIdOrderByAlertTimeAsc(fileId).stream()
        .map(IdsAlertLookupAdapter::facts)
        .toList();
  }

  static IdsAlertFacts facts(IdsAlertEntity e) {
    return new IdsAlertFacts(
        e.getConversationId(), e.getAlertTime(), e.getSrcIp(), e.getSrcPort(), e.getDstIp(),
        e.getDstPort(), e.getSid(), e.getRev(), e.getSignature(), e.getCategory(), e.getSeverity(),
        e.getSignatureSeverity(), e.getConfidence(), e.getAttackTarget(),
        e.getMetadata() == null ? Map.of() : e.getMetadata(), e.getHttpMethod(), e.getHttpHost(),
        e.getHttpUrl(), e.getHttpUserAgent(), e.getHttpStatus());
  }
}
