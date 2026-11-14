package com.tracepcap.analysis.service;

import com.tracepcap.analysis.entity.ConversationEntity;
import com.tracepcap.analysis.entity.HostClassificationEntity;
import com.tracepcap.analysis.entity.HostTtlWindowEntity;
import com.tracepcap.analysis.entity.IpOccupancyEntity;
import com.tracepcap.analysis.entity.WindowsLogonEntity;
import com.tracepcap.analysis.repository.ConversationRepository;
import com.tracepcap.analysis.repository.HostClassificationRepository;
import com.tracepcap.analysis.repository.HostTtlWindowRepository;
import com.tracepcap.analysis.repository.IpOccupancyRepository;
import com.tracepcap.analysis.repository.WindowsLogonRepository;
import com.tracepcap.analysis.spi.ClassificationHint;
import com.tracepcap.analysis.spi.HostClassifier;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.repository.FileRepository;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Classifies each device that held an address (#918 item 3, slice 2). An address two devices held
 * in turn used to be classified once, from both devices' traffic together, so a laptop and the
 * phone that got its address later came out as one host with the laptop's name and a blend of the
 * two devices' evidence.
 *
 * <p>Each occupancy is classified by the same classifier, from only what happened in its window:
 *
 * <ul>
 *   <li>the address's conversations that started in [startsAt, endsAt);
 *   <li>the occupancy's MAC (so the vendor is its own) and its DHCP hostname;
 *   <li>the TTL the address sent with during the window;
 *   <li>Windows sign-ins first seen in the window;
 *   <li>detection-rule votes from rules that matched a conversation in the window.
 * </ul>
 *
 * Service roles (DNS server and the like) are the address's, since the service logs aren't split by
 * time. Everything is read back from the database, so a manual split or merge is re-classified the
 * same way as the analysis.
 *
 * <p>The address's own row in {@code host_classifications} is left as it is.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class OccupancyClassificationService {

  private final IpOccupancyRepository occupancies;
  private final ConversationRepository conversations;
  private final HostTtlWindowRepository ttlWindows;
  private final WindowsLogonRepository logons;
  private final HostClassificationRepository hostClassifications;
  private final FileRepository files;
  private final HostClassifier classifier;

  /** Classifies every occupancy in the capture. Never throws: a failure leaves them unclassified. */
  @Transactional(noRollbackFor = RuntimeException.class)
  public void classifyFile(UUID fileId) {
    try {
      List<IpOccupancyEntity> all = occupancies.findByFileIdOrderByIpAscIdxAsc(fileId);
      if (all.isEmpty()) return;
      FileEntity file = files.findById(fileId).orElse(null);
      if (file == null) return;
      Map<String, List<IpOccupancyEntity>> byIp = new LinkedHashMap<>();
      for (IpOccupancyEntity o : all) byIp.computeIfAbsent(o.getIp(), k -> new ArrayList<>()).add(o);
      byIp.forEach((ip, occ) -> classify(file, ip, occ));
      log.info("Classified {} occupancies of {} reused address(es) in file {}", all.size(), byIp.size(), fileId);
    } catch (RuntimeException e) {
      log.warn("Failed to classify occupancies for file {}: {}", fileId, e.getMessage());
    }
  }

  /** Classifies one address's occupancies (after a split or merge). Never throws. */
  @Transactional(noRollbackFor = RuntimeException.class)
  public void classifyAddress(UUID fileId, String ip) {
    try {
      List<IpOccupancyEntity> occ = occupancies.findByFileIdAndIpOrderByIdx(fileId, ip);
      if (occ.isEmpty()) return;
      files.findById(fileId).ifPresent(file -> classify(file, ip, occ));
    } catch (RuntimeException e) {
      log.warn("Failed to classify occupancies of {} in file {}: {}", ip, fileId, e.getMessage());
    }
  }

  private void classify(FileEntity file, String ip, List<IpOccupancyEntity> occ) {
    UUID fileId = file.getId();
    List<ConversationEntity> convs = conversations.findByFileIdAndIp(fileId, ip);
    List<HostTtlWindowEntity> ttls = ttlWindows.findByFileIdAndIp(fileId, ip);
    List<WindowsLogonEntity> signIns = logons.findByFileIdAndIpOrderByFirstSeenAscIdAsc(fileId, ip);
    HostClassificationEntity address = hostClassifications.findFirstByFileIdAndIpOrderByIdAsc(fileId, ip).orElse(null);
    Set<String> roles = roles(address);
    List<ClassificationHint> addressVotes = RuleVoteRescoreService.boardOf(address == null ? new HostClassificationEntity() : address).ruleVotes();

    for (IpOccupancyEntity o : occ) {
      List<PcapParserService.ConversationInfo> mine = new ArrayList<>();
      Set<String> rulesSeen = new HashSet<>();
      for (ConversationEntity c : convs) {
        if (!within(c.getStartTime(), o)) continue;
        mine.add(toInfo(c));
        if (c.getCustomSignatures() != null) rulesSeen.addAll(Arrays.asList(c.getCustomSignatures()));
      }
      List<ClassificationHint> votes = addressVotes.stream().filter(v -> rulesSeen.contains(v.source())).toList();
      List<WindowsIdentityResolverService.Claim> claims = new ArrayList<>();
      String user = null;
      int userSeen = -1;
      for (WindowsLogonEntity l : signIns) {
        if (!within(l.getFirstSeen(), o) || "CUSTOM".equals(l.getFolderKind())) continue;
        claims.add(new WindowsIdentityResolverService.Claim(ip, l.getUsername(), l.getSource()));
        if (l.getSeenCount() > userSeen) {
          user = l.getUsername();
          userSeen = l.getSeenCount();
        }
      }
      Integer ttl = ttlFor(ttls, o);

      Map<String, Integer> ttlMap = new LinkedHashMap<>();
      if (ttl != null) ttlMap.put(ip, ttl);
      Map<String, String> macMap = new LinkedHashMap<>();
      if (o.getMac() != null) macMap.put(ip, o.getMac());
      Map<String, HostnameResolverService.ResolvedHostname> names = new LinkedHashMap<>();
      if (o.getHostname() != null) names.put(ip, new HostnameResolverService.ResolvedHostname(o.getHostname(), HostnameResolverService.SOURCE_DHCP));

      List<HostClassificationEntity> result =
          mine.isEmpty()
              ? List.of()
              : classifier.classify(
                  new HostClassifier.ClassificationRequest(
                      file,
                      mine,
                      ttlMap,
                      macMap,
                      votes.isEmpty() ? Map.of() : Map.of(ip, votes),
                      names,
                      roles.isEmpty() ? Map.of() : Map.of(ip, roles),
                      claims.isEmpty() ? Map.of() : Map.of(ip, claims)));
      HostClassificationEntity h = result.stream().filter(r -> ip.equals(r.getIp())).findFirst().orElse(null);
      o.setConversationCount((long) mine.size());
      o.setTtl(ttl);
      o.setLoggedInUser(user);
      if (h == null) {
        o.setDeviceType(null);
        o.setConfidence(null);
        o.setWinnerScore(null);
        o.setWinnerReasons(null);
        o.setRunnerUpType(null);
        o.setRunnerUpScore(null);
        o.setRunnerUpReasons(null);
        o.setManufacturer(null);
        continue;
      }
      o.setDeviceType(h.getDeviceType());
      o.setConfidence(h.getConfidence());
      o.setWinnerScore(h.getWinnerScore());
      o.setWinnerReasons(h.getWinnerReasons());
      o.setRunnerUpType(h.getRunnerUpType());
      o.setRunnerUpScore(h.getRunnerUpScore());
      o.setRunnerUpReasons(h.getRunnerUpReasons());
      o.setManufacturer(h.getManufacturer());
    }
    occupancies.saveAll(occ);
  }

  /** Whether {@code t} falls in the occupancy's [startsAt, endsAt); an unknown time counts for the first. */
  static boolean within(LocalDateTime t, IpOccupancyEntity o) {
    if (t == null) return o.getStartsAt() == null;
    return (o.getStartsAt() == null || !t.isBefore(o.getStartsAt())) && (o.getEndsAt() == null || t.isBefore(o.getEndsAt()));
  }

  /**
   * The TTL the address sent with during the occupancy: of the TTLs whose window overlaps it, the
   * one first seen inside it with the most packets, else the overlapping one with the most packets.
   */
  static Integer ttlFor(List<HostTtlWindowEntity> windows, IpOccupancyEntity o) {
    HostTtlWindowEntity inside = null;
    HostTtlWindowEntity overlapping = null;
    for (HostTtlWindowEntity w : windows) {
      boolean overlaps =
          (o.getEndsAt() == null || w.getFirstSeen().isBefore(o.getEndsAt()))
              && (o.getStartsAt() == null || !w.getLastSeen().isBefore(o.getStartsAt()));
      if (!overlaps) continue;
      if (within(w.getFirstSeen(), o) && (inside == null || w.getPackets() > inside.getPackets())) inside = w;
      if (overlapping == null || w.getPackets() > overlapping.getPackets()) overlapping = w;
    }
    HostTtlWindowEntity pick = inside != null ? inside : overlapping;
    return pick == null ? null : pick.getTtl();
  }

  private static Set<String> roles(HostClassificationEntity address) {
    Set<String> out = new HashSet<>();
    if (address == null || address.getServiceRoles() == null || address.getServiceRoles().isBlank()) return out;
    for (String r : address.getServiceRoles().split(",")) if (!r.isBlank()) out.add(r.trim());
    return out;
  }

  /** The fields the classifier reads, from the stored conversation. */
  static PcapParserService.ConversationInfo toInfo(ConversationEntity c) {
    PcapParserService.ConversationInfo i = new PcapParserService.ConversationInfo();
    i.setSrcIp(c.getSrcIp());
    i.setSrcPort(c.getSrcPort());
    i.setDstIp(c.getDstIp());
    i.setDstPort(c.getDstPort());
    i.setInitiatorIp(c.getInitiatorIp());
    i.setInitiatorPort(c.getInitiatorPort());
    i.setProtocol(c.getProtocol());
    i.setAppName(c.getAppName());
    i.setTsharkProtocol(c.getTsharkProtocol());
    i.setCategory(c.getCategory());
    i.setHostname(c.getHostname());
    i.setPacketCount(c.getPacketCount());
    i.setTotalBytes(c.getTotalBytes());
    i.setStartTime(c.getStartTime());
    i.setEndTime(c.getEndTime());
    if (c.getCustomSignatures() != null) i.setCustomSignatures(new ArrayList<>(Arrays.asList(c.getCustomSignatures())));
    return i;
  }
}
