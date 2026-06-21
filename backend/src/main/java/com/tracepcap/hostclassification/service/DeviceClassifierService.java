package com.tracepcap.hostclassification.service;

import com.tracepcap.analysis.entity.HostClassificationEntity;
import com.tracepcap.analysis.service.HostnameResolverService;
import com.tracepcap.analysis.service.PcapParserService;
import com.tracepcap.analysis.spi.HostClassifier;
import com.tracepcap.hostclassification.service.classifier.DeviceClassificationSignal;
import com.tracepcap.hostclassification.service.classifier.DeviceTypes;
import com.tracepcap.hostclassification.service.classifier.HostContext;
import com.tracepcap.hostclassification.service.classifier.HostProfile;
import com.tracepcap.hostclassification.service.classifier.ScoreBoard;
import com.tracepcap.file.entity.FileEntity;
import jakarta.annotation.PostConstruct;
import java.io.BufferedReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Classifies each unique host in a PCAP capture into a device category using a multi-signal
 * heuristic:
 *
 * <ol>
 *   <li><b>MAC OUI lookup</b> – first 3 octets of the MAC resolve to a vendor (Apple → mobile/
 *       laptop, Cisco → router, etc.)
 *   <li><b>TTL fingerprinting</b> – initial TTL ≈128 → Windows (laptop/desktop); ≈64 →
 *       Linux/Android/iOS (server, mobile, router)
 *   <li><b>nDPI app profile</b> – apps observed in conversations (streaming/social → mobile or
 *       laptop; DNS-only → router/server)
 *   <li><b>Traffic patterns</b> – hosts that only receive connections on well-known ports → server;
 *       very high peer count → router; limited app variety + low volume → IoT
 * </ol>
 *
 * <p>A YAML {@code device_type} override (set by CustomSignatureService) takes precedence over all
 * heuristics and sets confidence to 100.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class DeviceClassifierService implements HostClassifier {

  /** Score margin (winner − runner-up) that maps to 100% confidence; smaller margins scale down. */
  private static final int CONFIDENCE_MARGIN_FOR_FULL = 60;

  // -------------------------------------------------------------------------
  // OUI vendor lookup — loaded at startup from /usr/share/wireshark/manuf
  // -------------------------------------------------------------------------

  /** All registered classification signals, injected by Spring (extension seam — add a bean). */
  private final List<DeviceClassificationSignal> signals;

  @Value("${app.wireshark.manuf-path:/usr/share/wireshark/manuf}")
  private String manufFile;

  /** OUI (lower-case "aa:bb:cc") → short vendor name from the manuf file */
  private Map<String, String> ouiVendor = Collections.emptyMap();

  /** Vendor name substring (lower-case) → device-type hint. Checked in order; first match wins. */
  private static final Map<String, String> VENDOR_HINT_OVERLAY = new LinkedHashMap<>();

  static {
    VENDOR_HINT_OVERLAY.put("apple", DeviceTypes.MOBILE);
    VENDOR_HINT_OVERLAY.put("samsung", DeviceTypes.MOBILE);
    VENDOR_HINT_OVERLAY.put("google", DeviceTypes.MOBILE);
    VENDOR_HINT_OVERLAY.put("oneplus", DeviceTypes.MOBILE);
    VENDOR_HINT_OVERLAY.put("xiaomi", DeviceTypes.MOBILE);
    VENDOR_HINT_OVERLAY.put("cisco", DeviceTypes.ROUTER);
    VENDOR_HINT_OVERLAY.put("huawei", DeviceTypes.ROUTER);
    VENDOR_HINT_OVERLAY.put("tp-link", DeviceTypes.ROUTER);
    VENDOR_HINT_OVERLAY.put("tplink", DeviceTypes.ROUTER);
    VENDOR_HINT_OVERLAY.put("netgear", DeviceTypes.ROUTER);
    VENDOR_HINT_OVERLAY.put("asus", DeviceTypes.ROUTER);
    VENDOR_HINT_OVERLAY.put("ubiquiti", DeviceTypes.ROUTER);
    VENDOR_HINT_OVERLAY.put("mikrotik", DeviceTypes.ROUTER);
    VENDOR_HINT_OVERLAY.put("dell", DeviceTypes.LAPTOP_DESKTOP);
    VENDOR_HINT_OVERLAY.put("intel", DeviceTypes.LAPTOP_DESKTOP);
    VENDOR_HINT_OVERLAY.put("lenovo", DeviceTypes.LAPTOP_DESKTOP);
    VENDOR_HINT_OVERLAY.put("hewlett packard", DeviceTypes.LAPTOP_DESKTOP);
    VENDOR_HINT_OVERLAY.put("hp inc", DeviceTypes.LAPTOP_DESKTOP);
    VENDOR_HINT_OVERLAY.put("acer", DeviceTypes.LAPTOP_DESKTOP);
    VENDOR_HINT_OVERLAY.put("raspberry pi", DeviceTypes.IOT);
    VENDOR_HINT_OVERLAY.put("espressif", DeviceTypes.IOT);
    VENDOR_HINT_OVERLAY.put("arduino", DeviceTypes.IOT);
  }

  @PostConstruct
  void loadManufFile() {
    Path path = Path.of(manufFile);
    if (!Files.exists(path)) {
      log.warn("Wireshark manuf file not found at {}; OUI vendor lookup disabled", manufFile);
      return;
    }
    Map<String, String> mutable = new HashMap<>();
    int loaded = 0;
    try (BufferedReader br = Files.newBufferedReader(path)) {
      String line;
      while ((line = br.readLine()) != null) {
        if (line.startsWith("#") || line.isBlank()) continue;
        String[] parts = line.split("\t", 3);
        if (parts.length < 2) continue;
        String rawOui = parts[0].trim();
        if (rawOui.contains("/")) continue; // skip /28 and /36 MA-M / MA-S entries
        String oui = ouiKey(rawOui);
        if (oui == null) continue;

        String name =
            (parts.length >= 3 && !parts[2].isBlank() && !parts[2].trim().startsWith("#"))
                ? parts[2]
                : parts[1];
        int hashIdx = name.indexOf('#');
        if (hashIdx != -1) name = name.substring(0, hashIdx);
        name = name.trim();

        if (name.isEmpty()) continue;
        if (name.length() > 100) name = name.substring(0, 100);

        mutable.put(oui, name);
        loaded++;
      }
    } catch (Exception e) {
      log.warn("Failed to load Wireshark manuf file: {}", e.getMessage());
    }
    ouiVendor = Collections.unmodifiableMap(mutable);
    log.info("Loaded {} OUI entries from {}", loaded, manufFile);
  }

  // -------------------------------------------------------------------------
  // Classification
  // -------------------------------------------------------------------------

  /**
   * Classifies all unique IPs found in the conversations.
   *
   * @param file the FileEntity the conversations belong to
   * @param conversations parsed conversation list
   * @param hostTtls first-seen TTL per source IP
   * @param hostMacs first-seen MAC per source IP
   * @param deviceOverrides IP → custom device type string set by YAML rules (may be empty)
   * @param hostnames IP → passively-discovered hostname/source (may be empty)
   * @param serviceRolesByIp IP → service roles the host was detected serving, e.g. {@code "dns"}
   *     (may be empty); feeds role-aware signals and is recorded on each host
   * @return one HostClassificationEntity per unique IP
   */
  @Override
  public List<HostClassificationEntity> classify(
      FileEntity file,
      List<PcapParserService.ConversationInfo> conversations,
      Map<String, Integer> hostTtls,
      Map<String, String> hostMacs,
      Map<String, String> deviceOverrides,
      Map<String, HostnameResolverService.ResolvedHostname> hostnames,
      Map<String, Set<String>> serviceRolesByIp) {

    // Build per-host profiles from all conversations
    Map<String, HostProfile> profiles = new LinkedHashMap<>();
    for (PcapParserService.ConversationInfo conv : conversations) {
      addToProfile(profiles, conv.getSrcIp(), conv, true);
      addToProfile(profiles, conv.getDstIp(), conv, false);
    }

    List<HostClassificationEntity> results = new ArrayList<>();
    for (Map.Entry<String, HostProfile> entry : profiles.entrySet()) {
      String ip = entry.getKey();
      HostProfile profile = entry.getValue();

      Integer ttl = hostTtls.get(ip);
      String mac = hostMacs.get(ip);
      String manufacturer = resolveManufacturer(mac);
      String ouiHint = resolveOuiHint(mac);
      Set<String> roles = serviceRolesByIp.getOrDefault(ip, Set.of());

      // Check YAML device_type override first
      if (deviceOverrides.containsKey(ip)) {
        results.add(
            HostClassificationEntity.builder()
                .file(file)
                .ip(ip)
                .mac(mac)
                .manufacturer(manufacturer)
                .ttl(ttl)
                .deviceType(deviceOverrides.get(ip))
                .confidence(100)
                .serviceRoles(joinRoles(roles))
                .build());
        continue;
      }

      // Run every registered signal into a shared score board; the highest-scoring type wins.
      HostContext ctx = new HostContext(ip, profile, ttl, mac, manufacturer, ouiHint, null, roles);
      ScoreBoard board = new ScoreBoard();
      for (DeviceClassificationSignal signal : signals) {
        try {
          signal.contribute(ctx, board);
        } catch (Exception e) {
          log.warn("Classification signal '{}' failed for {}: {}", signal.name(), ip, e.getMessage());
        }
      }
      String deviceType = board.winner(DeviceTypes.UNKNOWN);
      int confidence = board.confidence(CONFIDENCE_MARGIN_FOR_FULL);

      results.add(
          HostClassificationEntity.builder()
              .file(file)
              .ip(ip)
              .mac(mac)
              .manufacturer(manufacturer)
              .ttl(ttl)
              .deviceType(deviceType)
              .confidence(confidence)
              .serviceRoles(joinRoles(roles))
              .build());
    }

    // Attach passively-discovered hostnames (DHCP/mDNS/NBNS/reverse DNS) to matching hosts.
    if (hostnames != null && !hostnames.isEmpty()) {
      for (HostClassificationEntity host : results) {
        HostnameResolverService.ResolvedHostname rh = hostnames.get(host.getIp());
        if (rh != null) {
          host.setHostname(rh.hostname());
          host.setHostnameSource(rh.source());
        }
      }
    }

    log.info("Classified {} hosts", results.size());
    return results;
  }

  // -------------------------------------------------------------------------
  // Internal helpers
  // -------------------------------------------------------------------------

  private void addToProfile(
      Map<String, HostProfile> profiles,
      String ip,
      PcapParserService.ConversationInfo conv,
      boolean isSrc) {

    if (ip == null) return;
    HostProfile p = profiles.computeIfAbsent(ip, k -> new HostProfile());

    p.totalBytes += conv.getTotalBytes() != null ? conv.getTotalBytes() : 0L;
    p.totalPackets += conv.getPacketCount() != null ? conv.getPacketCount() : 0L;
    p.conversationCount++;

    String app = conv.getAppName();
    if (app != null && !app.isBlank()) p.apps.add(app);

    String cat = conv.getCategory();
    if (cat != null && !cat.isBlank()) p.categories.add(cat);

    if (isSrc) {
      // This host initiated the conversation
      p.initiatedCount++;
      if (conv.getDstPort() != null) p.dstPorts.add(conv.getDstPort());
      p.peers.add(conv.getDstIp());
    } else {
      // This host received the conversation
      if (conv.getDstPort() != null) p.receivedOnPorts.add(conv.getDstPort());
      p.peers.add(conv.getSrcIp());
    }
  }

  private String resolveManufacturer(String mac) {
    String oui = ouiKey(mac);
    return oui != null ? ouiVendor.get(oui) : null;
  }

  private String resolveOuiHint(String mac) {
    String vendor = resolveManufacturer(mac);
    if (vendor == null) return null;
    String vendorLower = vendor.toLowerCase();
    for (Map.Entry<String, String> entry : VENDOR_HINT_OVERLAY.entrySet()) {
      if (vendorLower.contains(entry.getKey())) return entry.getValue();
    }
    return null;
  }

  private String ouiKey(String mac) {
    if (mac == null || mac.length() < 6) return null;
    // Normalise to lower-case colon form "aa:bb:cc"
    String norm = mac.toLowerCase().replace("-", ":").replace(".", ":");
    // Accept "aa:bb:cc:dd:ee:ff" or "aabbccddeeff" etc.
    if (norm.contains(":")) {
      String[] parts = norm.split(":");
      if (parts.length >= 3) return parts[0] + ":" + parts[1] + ":" + parts[2];
    } else if (norm.length() >= 6) {
      return norm.substring(0, 2) + ":" + norm.substring(2, 4) + ":" + norm.substring(4, 6);
    }
    return null;
  }

  /** Joins detected service roles into the comma-separated form stored on the host (null if none). */
  private String joinRoles(Set<String> roles) {
    return (roles == null || roles.isEmpty()) ? null : String.join(",", roles);
  }
}
