package com.tracepcap.monitor.service;

import com.tracepcap.analysis.spi.HostClassificationLookup;
import com.tracepcap.analysis.spi.HostClassificationLookup.HostFacts;
import com.tracepcap.common.dto.PagedResponse;
import com.tracepcap.common.exception.ResourceNotFoundException;
import com.tracepcap.common.net.MacKind;
import com.tracepcap.monitor.dto.NetworkDeviceCountsDto;
import com.tracepcap.monitor.dto.NetworkDeviceDto;
import com.tracepcap.monitor.entity.NetworkSnapshotEntity;
import com.tracepcap.monitor.repository.NetworkRepository;
import com.tracepcap.monitor.repository.NetworkSnapshotRepository;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * A network's devices across its snapshots (#918 slice 4, part a). A device is recognised by its
 * MAC; one on an address that more than one device held counts per device, not per address. Only
 * hosts with a MAC are devices here: a routed host's frames carry the router's MAC, so it has none.
 *
 * <p>Worked out at read time from each snapshot's hosts, so it follows re-analysis, splits and
 * merges with nothing to keep in step.
 */
@Service
@RequiredArgsConstructor
public class NetworkDeviceService {

  static final String HIGH = "high";
  static final String MEDIUM = "medium";
  static final String INFO = "info";

  private final NetworkRepository networks;
  private final NetworkSnapshotRepository snapshots;
  private final HostClassificationLookup hosts;
  private final JdbcTemplate jdbc;

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

  /** Every device, most recently seen first. */
  List<NetworkDeviceDto> devices(UUID networkId) {
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
    List<NetworkDeviceDto> out = new ArrayList<>();
    for (Acc a : byMac.values()) out.add(a.toDto());
    out.sort(
        Comparator.comparingInt((NetworkDeviceDto d) -> -lastSnapshot(d))
            .thenComparing(d -> d.getName() == null ? "" : d.getName(), String.CASE_INSENSITIVE_ORDER));
    return out;
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

  static boolean irregular(NetworkDeviceDto d) {
    return d.getFlags().stream().anyMatch(f -> !INFO.equals(f.getSeverity()));
  }

  private static boolean matches(NetworkDeviceDto d, String needle) {
    if (contains(d.getName(), needle) || contains(d.getMac(), needle) || contains(d.getVendor(), needle)
        || contains(d.getLabel(), needle)) return true;
    return d.getAddresses().stream().anyMatch(a -> contains(a.getIp(), needle));
  }

  private static boolean contains(String s, String needle) {
    return s != null && s.toLowerCase(Locale.ROOT).contains(needle);
  }

  private static int lastSnapshot(NetworkDeviceDto d) {
    return d.getAddresses().stream().mapToInt(NetworkDeviceDto.Address::getLastSnapshot).max().orElse(0);
  }

  /** One MAC's sightings, folded across snapshots in order. */
  private static final class Acc {
    final String mac;
    String name;
    String deviceType;
    String vendor;
    String label;
    UUID lastFileId;
    String lastKey;
    final Map<String, int[]> addresses = new LinkedHashMap<>();
    final Set<UUID> seen = new LinkedHashSet<>();
    final Set<String> warnings = new LinkedHashSet<>();

    Acc(String mac) {
      this.mac = mac;
    }

    void see(int n, UUID fileId, HostFacts h, String labelHere) {
      String ip = com.tracepcap.analysis.spi.DeviceKeys.ipOf(h.ip());
      int[] range = addresses.computeIfAbsent(ip, k -> new int[] {n, n});
      range[1] = Math.max(range[1], n);
      seen.add(fileId);
      // Later snapshots win: the device as it is now.
      name = h.hostname() != null && !h.hostname().isBlank() ? h.hostname() : ip;
      deviceType = h.deviceType();
      if (h.manufacturer() != null) vendor = h.manufacturer();
      if (labelHere != null) label = labelHere;
      lastFileId = fileId;
      lastKey = h.ip();
      if (h.identityWarning() != null) warnings.add(h.identityWarning());
    }

    NetworkDeviceDto toDto() {
      MacKind kind = MacKind.of(mac);
      List<NetworkDeviceDto.Flag> flags = new ArrayList<>();
      for (String w : warnings) {
        flags.add(flag("duplicate-mac", HIGH, "Duplicate MAC? " + w));
      }
      switch (kind) {
        case VIRTUAL_MACHINE ->
            flags.add(flag("vm-mac", MEDIUM,
                MacKind.hypervisor(mac) + " virtual machine MAC: VMs cloned from one image often share a MAC."));
        case CONTAINER ->
            flags.add(flag("container-mac", MEDIUM, "Docker-style MAC: a container, not a physical device."));
        case PRIVATE ->
            flags.add(flag("private-mac", INFO,
                "Private MAC: the device made it up, so it names no vendor and may change."));
        default -> {}
      }
      List<NetworkDeviceDto.Address> addrs = new ArrayList<>();
      addresses.forEach((ip, r) ->
          addrs.add(NetworkDeviceDto.Address.builder().ip(ip).firstSnapshot(r[0]).lastSnapshot(r[1]).build()));
      return NetworkDeviceDto.builder()
          .mac(mac)
          .name(name)
          .deviceType(deviceType)
          .vendor(kind == MacKind.PRIVATE && vendor == null ? null : vendor)
          .macKind(kind.name())
          .label(label)
          .addresses(addrs)
          .seenInFileIds(new ArrayList<>(seen))
          .lastFileId(lastFileId)
          .lastKey(lastKey)
          .flags(flags)
          .build();
    }

    private static NetworkDeviceDto.Flag flag(String kind, String severity, String text) {
      return NetworkDeviceDto.Flag.builder().kind(kind).severity(severity).text(text).build();
    }
  }
}
