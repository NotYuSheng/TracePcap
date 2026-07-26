package com.tracepcap.insights.service;

import com.tracepcap.analysis.spi.ConversationLookup;
import com.tracepcap.analysis.spi.ConversationLookup.ConversationFacts;
import com.tracepcap.analysis.spi.GeoOrgLookup;
import com.tracepcap.analysis.spi.GeoOrgLookup.IpPlace;
import com.tracepcap.analysis.spi.HostClassificationLookup;
import com.tracepcap.analysis.spi.HostClassificationLookup.HostFacts;
import com.tracepcap.insights.dto.HostIdentityEvidenceDto;
import com.tracepcap.insights.entity.HostIdentityEntity;
import com.tracepcap.insights.repository.HostIdentityRepository;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * Composes the full explainable-classification payload for one host (#556 follow-up): the
 * adjudicated identity plus the measured evidence axes, so any surface holding a {@code fileId + ip}
 * can render the "verdict, and why" experience that used to live only in the network graph.
 *
 * <p>The verdict comes from the adjudicated {@link HostIdentityEntity}; hardware/service facts from
 * {@link HostClassificationLookup}; and the behaviour facts (who opened the connection) plus the
 * nDPI app list are derived here from {@link ConversationLookup#conversationFactsForIp}, the same
 * per-IP fact base the frontend previously folded by hand off the whole graph.
 */
@Service
@RequiredArgsConstructor
public class HostIdentityEvidenceService {

  private final HostIdentityRepository hostIdentityRepository;
  private final HostIdentityService hostIdentityService;
  private final HostClassificationLookup hostClassificationLookup;
  private final ConversationLookup conversationLookup;
  private final GeoOrgLookup geoOrgLookup;

  /**
   * The identity + evidence for one host, or empty when the file has no such host. Lazily backfills
   * identities for legacy files (mirrors {@code HostIdentitiesController}) so a host classified
   * before the adjudicator existed still resolves a verdict.
   */
  public Optional<HostIdentityEvidenceDto> evidenceFor(UUID fileId, String ip) {
    Optional<HostFacts> factsOpt = hostClassificationLookup.hostFactsByIp(fileId, ip);
    if (factsOpt.isEmpty()) {
      return Optional.empty();
    }
    HostFacts facts = factsOpt.get();

    if (hostIdentityRepository.findByFileId(fileId).isEmpty()) {
      hostIdentityService.adjudicateFile(fileId);
    }
    HostIdentityEntity identity =
        hostIdentityRepository.findByFileId(fileId).stream()
            .filter(h -> ip.equals(h.getIp()))
            .findFirst()
            .orElse(null);

    // Behaviour + nDPI apps, folded from this IP's conversations (#496).
    //
    // initiated/answered are direction-gated (require a measured initiator); conversationCount and
    // the distinct-peer set are NOT — they are the raw fan-out the traffic-pattern signal weighs, so
    // the panel still shows real evidence on a capture where nDPI never measured flow direction.
    int initiated = 0;
    int answered = 0;
    int conversationCount = 0;
    Set<String> peers = new LinkedHashSet<>();
    Set<String> apps = new LinkedHashSet<>();
    for (ConversationFacts c : conversationLookup.conversationFactsForIp(fileId, ip)) {
      conversationCount++;
      String src = c.flow().srcIp();
      String dst = c.flow().dstIp();
      String peer = ip.equals(src) ? dst : src;
      if (peer != null && !peer.isBlank() && !ip.equals(peer)) {
        peers.add(peer);
      }
      String initiator = c.flow().initiatorIp();
      if (initiator != null) {
        if (ip.equals(initiator)) {
          initiated++;
        } else {
          answered++;
        }
      }
      String app = c.findings().appName();
      if (app != null && !app.isBlank()) {
        apps.add(app);
      }
    }

    HostIdentityEvidenceDto.HostIdentityEvidenceDtoBuilder b =
        HostIdentityEvidenceDto.builder()
            .ip(ip)
            .manufacturer(facts.manufacturer())
            .ttl(facts.ttl())
            .serviceRoles(new ArrayList<>(facts.serviceRoles()))
            .ndpiApps(new ArrayList<>(apps))
            .initiatedConversations(initiated)
            .answeredConversations(answered)
            .conversationCount(conversationCount)
            .peerCount(peers.size());

    // Geolocation for external hosts (INFERRED, provenance-carrying). Absent from the map for
    // private/internal IPs, which are never geolocated — the builder stays null and the panel omits
    // the block. This reads the persisted geo cache; it does not trigger a fresh lookup on view.
    IpPlace place = geoOrgLookup.placesFor(List.of(ip)).get(ip);
    if (place != null) {
      b.country(place.country())
          .countryCode(place.countryCode())
          .asn(place.asn())
          .org(place.org())
          .geoSource(place.geoSource());
    }

    if (identity != null) {
      b.primaryLabel(identity.getPrimaryLabel())
          .basis(identity.getBasis())
          .confidence(identity.getConfidence())
          .contested(identity.isContested())
          .candidates(identity.getCandidates());
    } else {
      // No adjudicated identity (e.g. a host with no conversations the adjudicator saw): fall back to
      // the raw classification so the surface still names something rather than blank.
      b.primaryLabel(facts.deviceType())
          .basis(HostIdentityEntity.BASIS_MACHINE)
          .confidence(facts.confidence())
          .contested(false)
          .candidates(List.of());
    }

    return Optional.of(b.build());
  }
}
