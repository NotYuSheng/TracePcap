package com.tracepcap.monitor.service;

import com.tracepcap.analysis.spi.DeviceKeys;
import com.tracepcap.analysis.spi.DeviceTraitLookup;
import com.tracepcap.analysis.spi.HostClassificationLookup;
import com.tracepcap.analysis.spi.HostClassificationLookup.HostFacts;
import com.tracepcap.common.dto.PagedResponse;
import com.tracepcap.common.exception.ResourceNotFoundException;
import com.tracepcap.common.net.MacKind;
import com.tracepcap.config.security.CurrentActor;
import com.tracepcap.governance.AuditLogService;
import com.tracepcap.governance.PermissionAction;
import com.tracepcap.governance.PermissionService;
import com.tracepcap.monitor.dto.DeviceLinkRequest;
import com.tracepcap.monitor.dto.DeviceLinkSuggestionDto;
import com.tracepcap.monitor.dto.NetworkDeviceCountsDto;
import com.tracepcap.monitor.dto.NetworkDeviceDto;
import com.tracepcap.monitor.entity.DeviceLinkEntity;
import com.tracepcap.monitor.entity.NetworkSnapshotEntity;
import com.tracepcap.monitor.repository.DeviceLinkRepository;
import com.tracepcap.monitor.repository.NetworkRepository;
import com.tracepcap.monitor.repository.NetworkSnapshotRepository;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * A network's devices across its snapshots (#918 slice 4). A device is recognised by its MAC; one
 * on an address that more than one device held counts per device, not per address. Only hosts with
 * a MAC are devices here: a routed host's frames carry the router's MAC, so it has none.
 *
 * <p><b>Private MACs</b> (4b): a phone may change its made-up MAC, and then shows up as two
 * devices. Two private MACs are <em>suggested</em> as one device when one stopped before the other
 * began and they share what a device keeps when its MAC changes (DHCP fingerprint, hostname, TLS
 * fingerprints, signed-in user), with nothing against it. Only the analyst links them.
 *
 * <p>Worked out at read time from each snapshot's hosts, so it follows re-analysis, splits and
 * merges; only the analyst's link decisions are stored.
 */
@Service
@RequiredArgsConstructor
public class NetworkDeviceService {

  static final String HIGH = "high";
  static final String MEDIUM = "medium";
  static final String INFO = "info";

  static final String STRONG = "strong";
  static final String WEAK = "weak";

  /** A hand-over this short (one MAC's last activity to the next one's first) is strong evidence. */
  static final Duration QUICK_HANDOVER = Duration.ofHours(1);

  /** A suggestion needs this much evidence besides the hand-over: strong = 3, medium = 2, weak = 1. */
  static final int SUGGEST_AT = 4;

  private static final String AUDIT_TARGET = "network-device";

  private final NetworkRepository networks;
  private final NetworkSnapshotRepository snapshots;
  private final HostClassificationLookup hosts;
  private final DeviceTraitLookup traits;
  private final DeviceLinkRepository links;
  private final JdbcTemplate jdbc;
  private final PermissionService permissionService;
  private final AuditLogService auditLog;
  private final CurrentActor currentActor;

  // ── Read ────────────────────────────────────────────────────────────────────

  /** {@code show}: all (null), irregular, or private. {@code q} matches name, MAC, address, vendor or label. */
  @Transactional(readOnly = true)
  public PagedResponse<NetworkDeviceDto> list(UUID networkId, String q, String show, int page, int pageSize) {
    List<NetworkDeviceDto> all = devices(networkId);
    String needle = q == null ? "" : q.trim().toLowerCase(Locale.ROOT);
    List<NetworkDeviceDto> out = new ArrayList<>();
    for (NetworkDeviceDto d : all) {
      if ("irregular".equals(show) && !irregular(d)) continue;
      if ("private".equals(show) && !MacKind.PRIVATE.name().equals(d.getMacKind())) continue;
      if (!needle.isEmpty() && !matches(d, needle)) continue;
      out.add(d);
    }
    return PagedResponse.of(out, Math.max(1, page), Math.max(1, Math.min(pageSize, 200)));
  }

  @Transactional(readOnly = true)
  public NetworkDeviceCountsDto counts(UUID networkId) {
    List<NetworkDeviceDto> all = devices(networkId);
    long irregular = all.stream().filter(NetworkDeviceService::irregular).count();
    long priv = all.stream().filter(d -> MacKind.PRIVATE.name().equals(d.getMacKind())).count();
    return new NetworkDeviceCountsDto(all.size(), irregular, priv);
  }

  /** Every device, most recently seen first; MACs an analyst linked are one device. */
  List<NetworkDeviceDto> devices(UUID networkId) {
    Map<String, Acc> byMac = sightings(networkId);
    List<DeviceLinkEntity> decided = links.findByNetworkIdOrderByIdAsc(networkId);

    // Union the MACs linked as the same device.
    Map<String, String> parent = new HashMap<>();
    for (DeviceLinkEntity l : decided) {
      if (!DeviceLinkEntity.SAME.equals(l.getDecision())) continue;
      if (!byMac.containsKey(l.getMacA()) || !byMac.containsKey(l.getMacB())) continue;
      parent.put(root(parent, l.getMacA()), root(parent, l.getMacB()));
    }
    Map<String, List<Acc>> groups = new LinkedHashMap<>();
    for (Acc a : byMac.values()) groups.computeIfAbsent(root(parent, a.mac), k -> new ArrayList<>()).add(a);

    List<NetworkDeviceDto> out = new ArrayList<>();
    for (List<Acc> g : groups.values()) {
      Set<String> macs = new HashSet<>();
      g.forEach(a -> macs.add(a.mac));
      List<NetworkDeviceDto.Link> mine = new ArrayList<>();
      for (DeviceLinkEntity l : decided) {
        if (macs.contains(l.getMacA()) || macs.contains(l.getMacB())) mine.add(toDto(l));
      }
      out.add(merge(g, mine));
    }
    out.sort(
        Comparator.comparingInt((NetworkDeviceDto d) -> -lastSnapshot(d))
            .thenComparing(d -> d.getName() == null ? "" : d.getName(), String.CASE_INSENSITIVE_ORDER));
    return out;
  }

  /**
   * Pairs of private MACs that look like one device and haven't been decided. Earlier MAC first;
   * strongest evidence first.
   */
  @Transactional(readOnly = true)
  public List<DeviceLinkSuggestionDto> suggestions(UUID networkId) {
    Map<String, Acc> byMac = sightings(networkId);
    Set<String> decided = new HashSet<>();
    for (DeviceLinkEntity l : links.findByNetworkIdOrderByIdAsc(networkId)) decided.add(l.getMacA() + "|" + l.getMacB());

    List<Acc> priv = new ArrayList<>();
    for (Acc a : byMac.values()) if (MacKind.of(a.mac) == MacKind.PRIVATE) priv.add(a);
    if (priv.size() > 300) priv = priv.subList(0, 300); // bound the pairwise check on a huge network
    Map<String, Traits> t = new HashMap<>();
    for (Acc a : priv) t.put(a.mac, traitsOf(a));

    List<Scored> found = new ArrayList<>();
    for (int i = 0; i < priv.size(); i++) {
      for (int j = i + 1; j < priv.size(); j++) {
        Acc x = priv.get(i);
        Acc y = priv.get(j);
        String[] pair = ordered(x.mac, y.mac);
        if (decided.contains(pair[0] + "|" + pair[1])) continue;
        Scored s = score(x, t.get(x.mac), y, t.get(y.mac));
        if (s != null) found.add(s);
      }
    }
    found.sort(Comparator.comparingInt((Scored s) -> -s.score));
    return found.stream().map(s -> s.dto).toList();
  }

  // ── Decisions ───────────────────────────────────────────────────────────────

  /** Records that two MACs are one device, or not. Needs HOST_OCCUPANCY; audited. */
  @Transactional
  public NetworkDeviceDto.Link decide(UUID networkId, DeviceLinkRequest req) {
    permissionService.require(PermissionAction.HOST_OCCUPANCY);
    if (!networks.existsById(networkId)) throw new ResourceNotFoundException("Network not found: " + networkId);
    String a = req.getMacA().toLowerCase(Locale.ROOT).replace('-', ':');
    String b = req.getMacB().toLowerCase(Locale.ROOT).replace('-', ':');
    if (a.equals(b)) throw new IllegalArgumentException("Pick two different MACs.");
    String[] pair = ordered(a, b);
    Map<String, Acc> byMac = sightings(networkId);
    if (!byMac.containsKey(pair[0]) || !byMac.containsKey(pair[1])) {
      throw new IllegalArgumentException("Both MACs must have been seen in this network's snapshots.");
    }
    if (links.findByNetworkIdAndMacAAndMacB(networkId, pair[0], pair[1]).isPresent()) {
      throw new IllegalArgumentException("Those two MACs are already decided; undo that first.");
    }
    if (DeviceLinkEntity.SAME.equals(req.getDecision()) && overlap(byMac.get(pair[0]), byMac.get(pair[1]))) {
      throw new IllegalArgumentException(
          "Both MACs were active in the same snapshot at the same time, so they're two devices.");
    }
    DeviceLinkEntity saved =
        links.save(
            DeviceLinkEntity.builder()
                .networkId(networkId)
                .macA(pair[0])
                .macB(pair[1])
                .decision(req.getDecision())
                .reason(req.getReason().trim())
                .actor(currentActor.username())
                .build());
    auditLog.record("network-device.link." + req.getDecision(), AUDIT_TARGET,
        networkId + "/" + pair[0] + "+" + pair[1], null, audit(saved));
    return toDto(saved);
  }

  /** Undoes a decision. Needs HOST_OCCUPANCY; audited. */
  @Transactional
  public void undo(UUID networkId, Long linkId) {
    permissionService.require(PermissionAction.HOST_OCCUPANCY);
    DeviceLinkEntity l =
        links.findById(linkId)
            .filter(x -> x.getNetworkId().equals(networkId))
            .orElseThrow(() -> new ResourceNotFoundException("Device link not found: " + linkId));
    links.delete(l);
    auditLog.record("network-device.link.undo", AUDIT_TARGET,
        networkId + "/" + l.getMacA() + "+" + l.getMacB(), audit(l), null);
  }

  // ── Internals ───────────────────────────────────────────────────────────────

  /** Every MAC's sightings across the network's snapshots, in snapshot order. */
  private Map<String, Acc> sightings(UUID networkId) {
    if (!networks.existsById(networkId)) throw new ResourceNotFoundException("Network not found: " + networkId);
    List<NetworkSnapshotEntity> chain = snapshots.findByNetworkIdOrderBySnapshotOrderAsc(networkId);
    Map<String, Acc> byMac = new LinkedHashMap<>();
    for (int i = 0; i < chain.size(); i++) {
      UUID fileId = chain.get(i).getFile().getId();
      int n = i + 1;
      Map<String, String> labelByKey = labels(fileId);
      for (HostFacts h : hosts.deviceInventory(fileId)) {
        if (h.mac() == null || h.mac().isBlank()) continue;
        if ("VIRTUAL_FAILOVER".equals(h.addressKind())) continue; // a shared router address, not a device
        String mac = h.mac().toLowerCase(Locale.ROOT);
        // A failover pair's shared MAC: the routers behind it are listed under their own MACs when
        // they have one, and the pair's address isn't a device.
        if (MacKind.of(mac) == MacKind.VIRTUAL_ROUTER) continue;
        Acc a = byMac.computeIfAbsent(mac, Acc::new);
        a.see(n, fileId, h, labelByKey.getOrDefault(h.ip(), labelByKey.get("mac:" + mac)));
      }
    }
    return byMac;
  }

  /** The analyst's confirmed role labels in a file: by IP or device key, and by MAC as "mac:…". */
  private Map<String, String> labels(UUID fileId) {
    Map<String, String> out = new HashMap<>();
    jdbc.query(
        "SELECT entity_type, entity_key, role_label FROM node_roles"
            + " WHERE file_id = ? AND confirmed_by_human = TRUE AND role_label IS NOT NULL",
        rs -> {
          String type = rs.getString(1);
          String key = rs.getString(2);
          String label = rs.getString(3);
          if ("IP".equalsIgnoreCase(type)) out.put(key, label);
          else if ("DEVICE".equalsIgnoreCase(type)) out.put("mac:" + key.toLowerCase(Locale.ROOT), label);
        },
        fileId);
    return out;
  }

  /** What a MAC showed of itself across its sightings. */
  private record Traits(
      Set<String> dhcp, Set<String> hostnames, Set<String> tls, Set<String> users,
      LocalDateTime first, LocalDateTime last) {}

  private Traits traitsOf(Acc a) {
    Set<String> dhcp = new TreeSet<>();
    Set<String> names = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
    Set<String> tls = new TreeSet<>();
    Set<String> users = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
    LocalDateTime first = null;
    LocalDateTime last = null;
    for (Sighting s : a.sightings) {
      var t = traits.traits(s.fileId, s.key, a.mac).orElse(null);
      if (t == null) continue;
      dhcp.addAll(t.dhcpFingerprints());
      if (t.hostname() != null && !t.hostname().isBlank()) names.add(t.hostname());
      tls.addAll(t.tlsFingerprints());
      if (t.loggedInUser() != null) users.add(t.loggedInUser());
      if (t.firstSeen() != null && (first == null || t.firstSeen().isBefore(first))) first = t.firstSeen();
      if (t.lastSeen() != null && (last == null || t.lastSeen().isAfter(last))) last = t.lastSeen();
    }
    return new Traits(dhcp, names, tls, users, first, last);
  }

  private record Scored(int score, DeviceLinkSuggestionDto dto) {}

  /**
   * Whether two private MACs look like one device, and why. Null when they don't: they were active
   * at the same time, something contradicts it (different DHCP fingerprints, hostnames or users),
   * or there isn't enough in common.
   */
  static Scored score(Acc x, Traits tx, Acc y, Traits ty) {
    if (tx == null || ty == null || tx.first == null || ty.first == null) return null;
    // Earlier first.
    if (ty.first.isBefore(tx.first)) {
      Acc sa = x; x = y; y = sa;
      Traits st = tx; tx = ty; ty = st;
    }
    if (!tx.last.isBefore(ty.first)) return null; // both active at once: two devices
    if (!tx.dhcp.isEmpty() && !ty.dhcp.isEmpty() && disjoint(tx.dhcp, ty.dhcp)) return null;
    if (!tx.hostnames.isEmpty() && !ty.hostnames.isEmpty() && disjoint(tx.hostnames, ty.hostnames)) return null;
    if (!tx.users.isEmpty() && !ty.users.isEmpty() && disjoint(tx.users, ty.users)) return null;

    List<DeviceLinkSuggestionDto.Evidence> ev = new ArrayList<>();
    int score = 0;
    Duration gap = Duration.between(tx.last, ty.first);
    ev.add(evidence(gap.compareTo(QUICK_HANDOVER) <= 0 ? STRONG : WEAK, "Hand-over in time",
        "One MAC was last active " + human(gap) + " before the other was first; they never overlapped."));
    if (!disjoint(tx.dhcp, ty.dhcp)) {
      score += 3;
      ev.add(evidence(STRONG, "Same DHCP fingerprint",
          "Both asked DHCP for the same options in the same order (" + shorten(common(tx.dhcp, ty.dhcp)) + ")."));
    }
    if (!disjoint(tx.users, ty.users)) {
      score += 3;
      ev.add(evidence(STRONG, "Same signed-in user", "Both were signed in as " + common(tx.users, ty.users) + "."));
    }
    if (!disjoint(tx.hostnames, ty.hostnames)) {
      score += 2;
      ev.add(evidence(MEDIUM, "Same hostname",
          "Both called themselves \"" + common(tx.hostnames, ty.hostnames) + "\". Hostnames can be shared, so not enough alone."));
    }
    if (!disjoint(tx.tls, ty.tls)) {
      score += 2;
      long n = tx.tls.stream().filter(ty.tls::contains).count();
      ev.add(evidence(MEDIUM, "Same TLS fingerprints",
          n + " TLS client fingerprint" + (n == 1 ? "" : "s") + " in common: the same software stack."));
    }
    if (score < SUGGEST_AT) return null;
    return new Scored(
        score,
        DeviceLinkSuggestionDto.builder()
            .macA(x.mac).nameA(x.name).firstSnapshotA(x.firstSnapshot).lastSnapshotA(x.lastSnapshot)
            .macB(y.mac).nameB(y.name).firstSnapshotB(y.firstSnapshot).lastSnapshotB(y.lastSnapshot)
            .evidence(ev)
            .build());
  }

  /** Whether two MACs were active in the same snapshot at the same time. */
  private boolean overlap(Acc a, Acc b) {
    Set<UUID> both = new HashSet<>(a.seen);
    both.retainAll(b.seen);
    if (both.isEmpty()) return false;
    Traits ta = traitsOf(a);
    Traits tb = traitsOf(b);
    if (ta.first == null || tb.first == null) return false;
    return !ta.last.isBefore(tb.first) && !tb.last.isBefore(ta.first);
  }

  private static DeviceLinkSuggestionDto.Evidence evidence(String strength, String what, String detail) {
    return DeviceLinkSuggestionDto.Evidence.builder().strength(strength).what(what).detail(detail).build();
  }

  private static boolean disjoint(Set<String> a, Set<String> b) {
    for (String s : a) if (b.contains(s)) return false;
    return true;
  }

  private static String common(Set<String> a, Set<String> b) {
    for (String s : a) if (b.contains(s)) return s;
    return "";
  }

  private static String shorten(String s) {
    return s.length() > 40 ? s.substring(0, 40) + "…" : s;
  }

  static String human(Duration d) {
    long minutes = Math.max(0, d.toMinutes());
    if (minutes < 60) return minutes + " min";
    long hours = minutes / 60;
    if (hours < 48) return hours + " h";
    return (hours / 24) + " days";
  }

  private static String[] ordered(String a, String b) {
    return a.compareTo(b) < 0 ? new String[] {a, b} : new String[] {b, a};
  }

  private static String root(Map<String, String> parent, String m) {
    String r = m;
    while (parent.containsKey(r)) r = parent.get(r);
    return r;
  }

  private static NetworkDeviceDto.Link toDto(DeviceLinkEntity l) {
    return NetworkDeviceDto.Link.builder()
        .id(l.getId()).macA(l.getMacA()).macB(l.getMacB()).decision(l.getDecision())
        .reason(l.getReason()).actor(l.getActor()).createdAt(l.getCreatedAt())
        .build();
  }

  private static Map<String, Object> audit(DeviceLinkEntity l) {
    Map<String, Object> m = new LinkedHashMap<>();
    m.put("macA", l.getMacA());
    m.put("macB", l.getMacB());
    m.put("decision", l.getDecision());
    m.put("reason", l.getReason());
    return m;
  }

  static boolean irregular(NetworkDeviceDto d) {
    return d.getFlags().stream().anyMatch(f -> !INFO.equals(f.getSeverity()));
  }

  private static boolean matches(NetworkDeviceDto d, String needle) {
    if (contains(d.getName(), needle) || contains(d.getVendor(), needle) || contains(d.getLabel(), needle)) return true;
    if (d.getMacs().stream().anyMatch(m -> contains(m, needle))) return true;
    return d.getAddresses().stream().anyMatch(a -> contains(a.getIp(), needle));
  }

  private static boolean contains(String s, String needle) {
    return s != null && s.toLowerCase(Locale.ROOT).contains(needle);
  }

  private static int lastSnapshot(NetworkDeviceDto d) {
    return d.getAddresses().stream().mapToInt(NetworkDeviceDto.Address::getLastSnapshot).max().orElse(0);
  }

  /** One sighting of a MAC: the file, and its key there. */
  private record Sighting(UUID fileId, String key) {}

  /** One MAC's sightings, folded across snapshots in order. */
  static final class Acc {
    final String mac;
    String name;
    String deviceType;
    String vendor;
    String label;
    UUID lastFileId;
    String lastKey;
    int firstSnapshot = Integer.MAX_VALUE;
    int lastSnapshot;
    final Map<String, int[]> addresses = new LinkedHashMap<>();
    final Set<UUID> seen = new LinkedHashSet<>();
    final Set<String> warnings = new LinkedHashSet<>();
    final List<Sighting> sightings = new ArrayList<>();

    Acc(String mac) {
      this.mac = mac;
    }

    void see(int n, UUID fileId, HostFacts h, String labelHere) {
      String ip = DeviceKeys.ipOf(h.ip());
      int[] range = addresses.computeIfAbsent(ip, k -> new int[] {n, n});
      range[1] = Math.max(range[1], n);
      seen.add(fileId);
      sightings.add(new Sighting(fileId, h.ip()));
      firstSnapshot = Math.min(firstSnapshot, n);
      lastSnapshot = Math.max(lastSnapshot, n);
      // Later snapshots win: the device as it is now.
      name = h.hostname() != null && !h.hostname().isBlank() ? h.hostname() : ip;
      deviceType = h.deviceType();
      if (h.manufacturer() != null) vendor = h.manufacturer();
      if (labelHere != null) label = labelHere;
      lastFileId = fileId;
      lastKey = h.ip();
      if (h.identityWarning() != null) warnings.add(h.identityWarning());
    }
  }

  /** One device from one or more linked MACs: the latest MAC's view, with everything seen under any. */
  private static NetworkDeviceDto merge(List<Acc> group, List<NetworkDeviceDto.Link> decided) {
    group.sort(Comparator.comparingInt((Acc a) -> a.lastSnapshot));
    Acc latest = group.get(group.size() - 1);
    Map<String, int[]> addresses = new LinkedHashMap<>();
    Set<UUID> seen = new LinkedHashSet<>();
    Set<String> warnings = new LinkedHashSet<>();
    List<String> macs = new ArrayList<>();
    String label = null;
    for (Acc a : group) {
      macs.add(a.mac);
      a.addresses.forEach((ip, r) -> {
        int[] m = addresses.computeIfAbsent(ip, k -> new int[] {r[0], r[1]});
        m[0] = Math.min(m[0], r[0]);
        m[1] = Math.max(m[1], r[1]);
      });
      seen.addAll(a.seen);
      warnings.addAll(a.warnings);
      if (a.label != null) label = a.label;
    }
    MacKind kind = MacKind.of(latest.mac);
    List<NetworkDeviceDto.Flag> flags = new ArrayList<>();
    for (String w : warnings) flags.add(flag("duplicate-mac", HIGH, "Duplicate MAC? " + w));
    switch (kind) {
      case VIRTUAL_MACHINE ->
          flags.add(flag("vm-mac", MEDIUM,
              MacKind.hypervisor(latest.mac) + " virtual machine MAC: VMs cloned from one image often share a MAC."));
      case CONTAINER ->
          flags.add(flag("container-mac", MEDIUM, "Docker-style MAC: a container, not a physical device."));
      case PRIVATE ->
          flags.add(flag("private-mac", INFO,
              group.size() > 1
                  ? "Private MAC: linked with " + (group.size() - 1) + " earlier MAC" + (group.size() > 2 ? "s" : "") + " as one device."
                  : "Private MAC: the device made it up, so it names no vendor and may change."));
      default -> {}
    }
    List<NetworkDeviceDto.Address> addrs = new ArrayList<>();
    addresses.forEach((ip, r) ->
        addrs.add(NetworkDeviceDto.Address.builder().ip(ip).firstSnapshot(r[0]).lastSnapshot(r[1]).build()));
    addrs.sort(Comparator.comparingInt(NetworkDeviceDto.Address::getFirstSnapshot));
    return NetworkDeviceDto.builder()
        .mac(latest.mac)
        .macs(macs)
        .name(latest.name)
        .deviceType(latest.deviceType)
        .vendor(latest.vendor)
        .macKind(kind.name())
        .label(label)
        .addresses(addrs)
        .seenInFileIds(new ArrayList<>(seen))
        .lastFileId(latest.lastFileId)
        .lastKey(latest.lastKey)
        .flags(flags)
        .links(decided)
        .build();
  }

  private static NetworkDeviceDto.Flag flag(String kind, String severity, String text) {
    return NetworkDeviceDto.Flag.builder().kind(kind).severity(severity).text(text).build();
  }
}
