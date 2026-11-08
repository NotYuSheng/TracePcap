package com.tracepcap.analysis.service;

import com.tracepcap.analysis.dto.occupancy.HostOccupancyResponse;
import com.tracepcap.analysis.dto.occupancy.OccupancyDecisionRequest;
import com.tracepcap.analysis.entity.DhcpLeaseEntity;
import com.tracepcap.analysis.entity.HostClassificationEntity;
import com.tracepcap.analysis.entity.IpMacObservationEntity;
import com.tracepcap.analysis.entity.IpOccupancyEntity;
import com.tracepcap.analysis.entity.OccupancyDecisionEntity;
import com.tracepcap.analysis.repository.ConversationRepository;
import com.tracepcap.analysis.repository.DhcpLeaseRepository;
import com.tracepcap.analysis.repository.HostClassificationRepository;
import com.tracepcap.analysis.repository.IpMacObservationRepository;
import com.tracepcap.analysis.repository.IpOccupancyRepository;
import com.tracepcap.analysis.repository.OccupancyDecisionRepository;
import com.tracepcap.common.exception.ResourceNotFoundException;
import com.tracepcap.config.security.CurrentActor;
import com.tracepcap.file.repository.FileRepository;
import com.tracepcap.governance.AuditLogService;
import com.tracepcap.governance.PermissionAction;
import com.tracepcap.governance.PermissionService;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Time-bounded host occupancy (#918 item 3, slice 1): which device held an address when, from ARP
 * ownership claims and DHCP leases, corrected by the analyst's split and merge decisions. Derived
 * rows are recomputed from the evidence and the decisions, so a re-run never loses a decision.
 *
 * <p>Slice 1 records and shows occupancies; nothing keys on them yet.
 */
@Service
@RequiredArgsConstructor
public class HostOccupancyService {

  /** A silence at least this long is offered as a split point. */
  static final Duration SILENCE = Duration.ofMinutes(10);

  private static final int MAX_SUGGESTIONS = 10;
  private static final String AUDIT_TARGET = "host-occupancy";

  private final IpMacObservationRepository observations;
  private final DhcpLeaseRepository leases;
  private final OccupancyDecisionRepository decisions;
  private final IpOccupancyRepository occupancies;
  private final ConversationRepository conversations;
  private final HostClassificationRepository hostClassifications;
  private final FileRepository files;
  private final PermissionService permissionService;
  private final AuditLogService auditLog;
  private final CurrentActor currentActor;

  // ── Analysis ────────────────────────────────────────────────────────────────

  /**
   * Stores the capture's DHCP leases. Joins the analysis transaction; a failure here is logged by
   * the caller and mustn't roll the analysis back.
   */
  @Transactional(noRollbackFor = RuntimeException.class)
  public void saveLeases(UUID fileId, List<DhcpLeaseResolverService.Lease> found) {
    leases.deleteAll(leases.findByFileId(fileId));
    if (found == null || found.isEmpty()) return;
    List<DhcpLeaseEntity> rows = new ArrayList<>();
    for (var l : found) {
      rows.add(
          DhcpLeaseEntity.builder()
              .fileId(fileId)
              .ip(l.ip())
              .mac(l.mac())
              .hostname(l.hostname())
              .firstSeen(l.firstSeen())
              .lastSeen(l.lastSeen())
              .build());
    }
    leases.saveAll(rows);
  }

  /**
   * Recomputes every address's occupancies in the capture and returns how many each address with
   * more than one has. {@code virtualIps} are never split automatically; null reads them from the
   * host classifications. Like {@link #saveLeases}, a failure mustn't roll the analysis back.
   */
  @Transactional(noRollbackFor = RuntimeException.class)
  public Map<String, Integer> recompute(UUID fileId, Set<String> virtualIps) {
    occupancies.deleteByFileId(fileId);
    Map<String, List<OccupancyBuilder.MacWindow>> windows = windowsByIp(fileId, null);
    Map<String, List<OccupancyBuilder.Decision>> decided = new HashMap<>();
    for (var d : decisions.findByFileId(fileId)) {
      decided.computeIfAbsent(d.getIp(), k -> new ArrayList<>()).add(toDecision(d));
    }
    Set<String> ips = new HashSet<>(decided.keySet());
    windows.forEach((ip, w) -> {
      if (w.stream().map(OccupancyBuilder.MacWindow::mac).distinct().count() > 1) ips.add(ip);
    });
    Set<String> virtual = virtualIps != null ? virtualIps : virtualIps(fileId);
    Map<String, Integer> counts = new TreeMap<>();
    for (String ip : ips) {
      var result = OccupancyBuilder.build(windows.get(ip), decided.get(ip), !virtual.contains(ip));
      if (save(fileId, ip, result) > 1) counts.put(ip, result.occupancies().size());
    }
    return counts;
  }

  // ── Read ────────────────────────────────────────────────────────────────────

  @Transactional(readOnly = true)
  public HostOccupancyResponse view(UUID fileId, String ip) {
    requireFile(fileId);
    var windows = windowsByIp(fileId, ip).getOrDefault(ip, List.of());
    List<OccupancyDecisionEntity> ds = decisions.findByFileIdAndIpOrderByAt(fileId, ip);
    boolean virtual = virtualIps(fileId).contains(ip);
    var result = OccupancyBuilder.build(windows, ds.stream().map(HostOccupancyService::toDecision).toList(), !virtual);
    Set<LocalDateTime> automatic = new HashSet<>(result.automaticBoundaries());

    List<LocalDateTime[]> times = conversationTimes(fileId, ip);
    List<HostOccupancyResponse.Occupancy> occ = new ArrayList<>();
    for (var o : result.occupancies()) {
      long n =
          times.stream()
              .filter(t -> t[0] != null)
              .filter(t -> o.startsAt() == null || !t[0].isBefore(o.startsAt()))
              .filter(t -> o.endsAt() == null || t[0].isBefore(o.endsAt()))
              .count();
      occ.add(
          HostOccupancyResponse.Occupancy.builder()
              .idx(o.idx())
              .mac(o.mac())
              .hostname(o.hostname())
              .startsAt(o.startsAt())
              .endsAt(o.endsAt())
              .startSource(o.startSource())
              .startEvidence(o.startEvidence())
              .boundaryKey(o.startsAt() == null ? null : o.startsAt().toString())
              .automatic(o.startsAt() != null && automatic.contains(o.startsAt()))
              .conversations(n)
              .build());
    }
    Set<LocalDateTime> boundaries = new HashSet<>();
    result.occupancies().forEach(o -> { if (o.startsAt() != null) boundaries.add(o.startsAt()); });

    boolean canEdit = permissionService.can(PermissionAction.HOST_OCCUPANCY);
    return HostOccupancyResponse.builder()
        .ip(ip)
        .firstActivity(times.isEmpty() ? null : times.get(0)[0])
        .lastActivity(lastActivity(times))
        .overlapping(result.overlapping())
        .virtualAddress(virtual)
        .occupancies(occ)
        .decisions(ds.stream().map(HostOccupancyService::toDto).toList())
        .suggestions(suggestions(windows, times, boundaries))
        .canEdit(canEdit)
        .editReason(canEdit ? null : permissionService.reason(PermissionAction.HOST_OCCUPANCY))
        .build();
  }

  // ── Analyst decisions ─────────────────────────────────────────────────────────

  /** Records a split or merge and recomputes the address. Needs HOST_OCCUPANCY; audited. */
  @Transactional
  public HostOccupancyResponse decide(UUID fileId, String ip, OccupancyDecisionRequest request) {
    permissionService.require(PermissionAction.HOST_OCCUPANCY);
    requireFile(fileId);
    LocalDateTime at = request.getAt();
    String action = request.getAction();
    if (OccupancyDecisionEntity.SPLIT.equals(action)) {
      List<LocalDateTime[]> times = conversationTimes(fileId, ip);
      LocalDateTime first = times.isEmpty() ? null : times.get(0)[0];
      LocalDateTime last = lastActivity(times);
      if (first == null || !at.isAfter(first) || at.isAfter(last)) {
        throw new IllegalArgumentException(
            "A split needs activity on both sides: pick a time after " + ip + "'s first conversation"
                + " and no later than its last.");
      }
    } else {
      var windows = windowsByIp(fileId, ip).getOrDefault(ip, List.of());
      var auto = OccupancyBuilder.build(windows, List.of(), !virtualIps(fileId).contains(ip)).automaticBoundaries();
      if (!auto.contains(at)) {
        throw new IllegalArgumentException("There's no automatic boundary at " + at + " to merge.");
      }
    }
    boolean exists =
        decisions.findByFileIdAndIpOrderByAt(fileId, ip).stream()
            .anyMatch(d -> d.getAt().equals(at) && d.getAction().equals(action));
    if (exists) throw new IllegalArgumentException("That " + action + " is already recorded.");

    OccupancyDecisionEntity e =
        decisions.save(
            OccupancyDecisionEntity.builder()
                .fileId(fileId)
                .ip(ip)
                .at(at)
                .action(action)
                .reason(request.getReason().trim())
                .actor(currentActor.username())
                .build());
    auditLog.record("host-occupancy." + action, AUDIT_TARGET, fileId + "/" + ip, null, auditView(e));
    recomputeOne(fileId, ip);
    return view(fileId, ip);
  }

  /** Undoes a decision. Needs HOST_OCCUPANCY; audited. */
  @Transactional
  public void undo(UUID fileId, String ip, Long decisionId) {
    permissionService.require(PermissionAction.HOST_OCCUPANCY);
    OccupancyDecisionEntity e =
        decisions
            .findById(decisionId)
            .filter(d -> d.getFileId().equals(fileId) && d.getIp().equals(ip))
            .orElseThrow(() -> new ResourceNotFoundException("Decision not found: " + decisionId));
    decisions.delete(e);
    auditLog.record("host-occupancy.undo", AUDIT_TARGET, fileId + "/" + ip, auditView(e), null);
    recomputeOne(fileId, ip);
  }

  /** A re-analysis version (#951) starts with its original's decisions. */
  @Transactional
  public void copyDecisions(UUID fromFileId, UUID toFileId) {
    List<OccupancyDecisionEntity> copies = new ArrayList<>();
    for (var d : decisions.findByFileId(fromFileId)) {
      copies.add(
          OccupancyDecisionEntity.builder()
              .fileId(toFileId)
              .ip(d.getIp())
              .at(d.getAt())
              .action(d.getAction())
              .reason(d.getReason())
              .actor(d.getActor())
              .build());
    }
    if (!copies.isEmpty()) decisions.saveAll(copies);
  }

  // ── Internals ───────────────────────────────────────────────────────────────

  private void recomputeOne(UUID fileId, String ip) {
    occupancies.deleteByFileIdAndIp(fileId, ip);
    var windows = windowsByIp(fileId, ip).getOrDefault(ip, List.of());
    var ds = decisions.findByFileIdAndIpOrderByAt(fileId, ip).stream().map(HostOccupancyService::toDecision).toList();
    save(fileId, ip, OccupancyBuilder.build(windows, ds, !virtualIps(fileId).contains(ip)));
  }

  /** Saves the occupancies when there's more than one; returns how many there are. */
  private int save(UUID fileId, String ip, OccupancyBuilder.Result result) {
    int n = result.occupancies().size();
    if (n < 2) return n;
    List<IpOccupancyEntity> rows = new ArrayList<>();
    for (var o : result.occupancies()) {
      rows.add(
          IpOccupancyEntity.builder()
              .fileId(fileId)
              .ip(ip)
              .idx(o.idx())
              .mac(o.mac())
              .hostname(o.hostname())
              .startsAt(o.startsAt())
              .endsAt(o.endsAt())
              .startSource(o.startSource())
              .startEvidence(o.startEvidence())
              .build());
    }
    occupancies.saveAll(rows);
    return n;
  }

  /** ARP claims (with times) and DHCP leases as MAC windows, by IP; {@code onlyIp} narrows it. */
  private Map<String, List<OccupancyBuilder.MacWindow>> windowsByIp(UUID fileId, String onlyIp) {
    Map<String, List<OccupancyBuilder.MacWindow>> out = new LinkedHashMap<>();
    List<IpMacObservationEntity> obs =
        onlyIp == null ? observations.findByFileId(fileId) : observations.findByFileIdAndIpOrderById(fileId, onlyIp);
    for (var o : obs) {
      if (o.getFirstSeen() == null || o.getLastSeen() == null) continue;
      out.computeIfAbsent(o.getIp(), k -> new ArrayList<>())
          .add(new OccupancyBuilder.MacWindow(o.getMac(), o.getFirstSeen(), o.getLastSeen(), "arp", null));
    }
    List<DhcpLeaseEntity> ls = onlyIp == null ? leases.findByFileId(fileId) : leases.findByFileIdAndIp(fileId, onlyIp);
    for (var l : ls) {
      out.computeIfAbsent(l.getIp(), k -> new ArrayList<>())
          .add(new OccupancyBuilder.MacWindow(l.getMac(), l.getFirstSeen(), l.getLastSeen(), "dhcp", l.getHostname()));
    }
    return out;
  }

  private Set<String> virtualIps(UUID fileId) {
    Set<String> out = new HashSet<>();
    for (HostClassificationEntity h : hostClassifications.findByFileId(fileId)) {
      if (HostIdentityChecks.VIRTUAL_FAILOVER.equals(h.getAddressKind())) out.add(h.getIp());
    }
    return out;
  }

  private List<LocalDateTime[]> conversationTimes(UUID fileId, String ip) {
    List<LocalDateTime[]> out = new ArrayList<>();
    for (Object[] row : conversations.findTimesByFileIdAndIp(fileId, ip)) {
      out.add(new LocalDateTime[] {(LocalDateTime) row[0], (LocalDateTime) row[1]});
    }
    return out;
  }

  private static LocalDateTime lastActivity(List<LocalDateTime[]> times) {
    LocalDateTime last = null;
    for (var t : times) {
      LocalDateTime end = t[1] != null ? t[1] : t[0];
      if (end != null && (last == null || end.isAfter(last))) last = end;
    }
    return last;
  }

  /**
   * Points worth splitting at that aren't boundaries already: a MAC that first claimed the address
   * (when overlapping claims stopped an automatic split), a DHCP hostname appearing, and long
   * silences between conversations.
   */
  static List<HostOccupancyResponse.Suggestion> suggestions(
      List<OccupancyBuilder.MacWindow> windows, List<LocalDateTime[]> times, Set<LocalDateTime> boundaries) {
    Map<LocalDateTime, HostOccupancyResponse.Suggestion> out = new TreeMap<>();
    LocalDateTime firstActivity = times.isEmpty() ? null : times.get(0)[0];

    Map<String, LocalDateTime> firstByMac = new HashMap<>();
    Map<String, String> hostnameByMac = new HashMap<>();
    for (var w : windows) {
      firstByMac.merge(w.mac(), w.first(), (a, b) -> a.isBefore(b) ? a : b);
      if (w.hostname() != null) hostnameByMac.put(w.mac(), w.hostname());
    }
    LocalDateTime earliest = firstByMac.values().stream().min(Comparator.naturalOrder()).orElse(null);
    firstByMac.forEach((mac, at) -> {
      if (at.equals(earliest) || boundaries.contains(at)) return;
      if (firstActivity != null && !at.isAfter(firstActivity)) return;
      String name = hostnameByMac.get(mac);
      out.putIfAbsent(at, suggestion(at, name != null ? "dhcp" : "mac",
          (name != null ? "DHCP: " + name + " (" + mac + ")" : mac) + " first claimed the address"));
    });

    record Gap(HostOccupancyResponse.Suggestion suggestion, long minutes) {}
    LocalDateTime reach = null;
    List<Gap> gaps = new ArrayList<>();
    for (var t : times) {
      if (t[0] == null) continue;
      if (reach != null && Duration.between(reach, t[0]).compareTo(SILENCE) >= 0 && !boundaries.contains(t[0])) {
        long minutes = Duration.between(reach, t[0]).toMinutes();
        gaps.add(new Gap(suggestion(t[0], "silence", "No traffic for " + humanMinutes(minutes) + " before this"), minutes));
      }
      LocalDateTime end = t[1] != null ? t[1] : t[0];
      if (reach == null || end.isAfter(reach)) reach = end;
    }
    // Keep the longest silences; the TreeMap puts them back in time order.
    gaps.sort(Comparator.comparingLong(Gap::minutes).reversed());
    for (var g : gaps) {
      if (out.size() >= MAX_SUGGESTIONS) break;
      out.putIfAbsent(g.suggestion().getAt(), g.suggestion());
    }
    return new ArrayList<>(out.values());
  }

  private static HostOccupancyResponse.Suggestion suggestion(LocalDateTime at, String kind, String description) {
    return HostOccupancyResponse.Suggestion.builder()
        .at(at)
        .key(at.toString())
        .kind(kind)
        .description(description)
        .build();
  }

  private static String humanMinutes(long minutes) {
    if (minutes < 60) return minutes + " min";
    long h = minutes / 60;
    long m = minutes % 60;
    return m == 0 ? h + " h" : h + " h " + m + " min";
  }

  private void requireFile(UUID fileId) {
    if (!files.existsById(fileId)) throw new ResourceNotFoundException("Capture not found: " + fileId);
  }

  private static OccupancyBuilder.Decision toDecision(OccupancyDecisionEntity d) {
    return new OccupancyBuilder.Decision(d.getAt(), d.getAction(), d.getActor(), d.getReason());
  }

  private static HostOccupancyResponse.Decision toDto(OccupancyDecisionEntity d) {
    return HostOccupancyResponse.Decision.builder()
        .id(d.getId())
        .at(d.getAt())
        .action(d.getAction())
        .reason(d.getReason())
        .actor(d.getActor())
        .createdAt(d.getCreatedAt())
        .build();
  }

  private static Map<String, Object> auditView(OccupancyDecisionEntity e) {
    Map<String, Object> m = new LinkedHashMap<>();
    m.put("ip", e.getIp());
    m.put("at", e.getAt().toString());
    m.put("action", e.getAction());
    m.put("reason", e.getReason());
    return m;
  }
}
