package com.tracepcap.analysis.service;

import com.tracepcap.analysis.entity.HostClassificationEntity;
import com.tracepcap.file.entity.FileEntity;
import jakarta.annotation.PostConstruct;
import java.io.BufferedReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;
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
public class DeviceClassifierService {

  // -------------------------------------------------------------------------
  // Device type constants
  // -------------------------------------------------------------------------

  public static final String ROUTER = "ROUTER";
  public static final String MOBILE = "MOBILE";
  public static final String LAPTOP_DESKTOP = "LAPTOP_DESKTOP";
  public static final String SERVER = "SERVER";
  public static final String IOT = "IOT";
  public static final String UNKNOWN = "UNKNOWN";

  // -------------------------------------------------------------------------
  // OUI vendor lookup — loaded at startup from /usr/share/wireshark/manuf
  // -------------------------------------------------------------------------

  @Value("${app.wireshark.manuf-path:/usr/share/wireshark/manuf}")
  private String manufFile;

  /** OUI (lower-case "aa:bb:cc") → short vendor name from the manuf file */
  private Map<String, String> ouiVendor = Collections.emptyMap();

  /**
   * Vendor name substring (lower-case) → device-type hint.
   * Checked in order; first match wins.
   */
  private static final Map<String, String> VENDOR_HINT_OVERLAY = new LinkedHashMap<>();

  static {
    VENDOR_HINT_OVERLAY.put("apple", MOBILE);
    VENDOR_HINT_OVERLAY.put("samsung", MOBILE);
    VENDOR_HINT_OVERLAY.put("google", MOBILE);
    VENDOR_HINT_OVERLAY.put("oneplus", MOBILE);
    VENDOR_HINT_OVERLAY.put("xiaomi", MOBILE);
    VENDOR_HINT_OVERLAY.put("cisco", ROUTER);
    VENDOR_HINT_OVERLAY.put("huawei", ROUTER);
    VENDOR_HINT_OVERLAY.put("tp-link", ROUTER);
    VENDOR_HINT_OVERLAY.put("tplink", ROUTER);
    VENDOR_HINT_OVERLAY.put("netgear", ROUTER);
    VENDOR_HINT_OVERLAY.put("asus", ROUTER);
    VENDOR_HINT_OVERLAY.put("ubiquiti", ROUTER);
    VENDOR_HINT_OVERLAY.put("mikrotik", ROUTER);
    VENDOR_HINT_OVERLAY.put("dell", LAPTOP_DESKTOP);
    VENDOR_HINT_OVERLAY.put("intel", LAPTOP_DESKTOP);
    VENDOR_HINT_OVERLAY.put("lenovo", LAPTOP_DESKTOP);
    VENDOR_HINT_OVERLAY.put("hewlett packard", LAPTOP_DESKTOP);
    VENDOR_HINT_OVERLAY.put("hp inc", LAPTOP_DESKTOP);
    VENDOR_HINT_OVERLAY.put("acer", LAPTOP_DESKTOP);
    VENDOR_HINT_OVERLAY.put("raspberry pi", IOT);
    VENDOR_HINT_OVERLAY.put("espressif", IOT);
    VENDOR_HINT_OVERLAY.put("arduino", IOT);
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
        String oui = parts[0].trim();
        if (oui.contains("/")) continue; // skip /28 and /36 MA-M / MA-S entries
        mutable.put(oui.toLowerCase(), parts[1].trim());
        loaded++;
      }
    } catch (Exception e) {
      log.warn("Failed to load Wireshark manuf file: {}", e.getMessage());
    }
    ouiVendor = Collections.unmodifiableMap(mutable);
    log.info("Loaded {} OUI entries from {}", loaded, manufFile);
  }

  // -------------------------------------------------------------------------
  // App profile signals
  // -------------------------------------------------------------------------

  /** nDPI apps strongly associated with mobile devices */
  private static final Set<String> MOBILE_APPS =
      Set.of(
          "Instagram", "TikTok", "Snapchat", "WhatsApp", "WeChat", "Line", "Viber",
          "Telegram", "Signal", "iMessage", "FaceTime", "AirDrop", "Siri");

  /** nDPI apps/categories suggesting a laptop/desktop */
  private static final Set<String> DESKTOP_APPS =
      Set.of(
          "Zoom", "Teams", "Slack", "Discord", "Skype", "WebEx", "GoToMeeting",
          "BitTorrent", "Steam", "Battle.net", "League of Legends", "Valorant",
          "Remote Desktop", "SSH", "SMB", "NFS", "VNC", "TeamViewer");

  /** nDPI apps associated with server or infrastructure roles */
  private static final Set<String> SERVER_APPS =
      Set.of("PostgreSQL", "MySQL", "MongoDB", "Redis", "Elasticsearch", "Kafka",
             "RabbitMQ", "Memcached", "LDAP", "Kerberos", "SNMP", "Syslog");

  /** nDPI categories strongly associated with IoT / embedded devices */
  private static final Set<String> IOT_CATEGORIES = Set.of("IoT-Scada", "Cloud");

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
   * @return one HostClassificationEntity per unique IP
   */
  public List<HostClassificationEntity> classify(
      FileEntity file,
      List<PcapParserService.ConversationInfo> conversations,
      Map<String, Integer> hostTtls,
      Map<String, String> hostMacs,
      Map<String, String> deviceOverrides) {

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
                .build());
        continue;
      }

      Map<String, Integer> scores = new HashMap<>();
      String deviceType = scoreAndClassify(ip, profile, ttl, ouiHint, scores);
      int confidence = computeConfidence(scores);

      results.add(
          HostClassificationEntity.builder()
              .file(file)
              .ip(ip)
              .mac(mac)
              .manufacturer(manufacturer)
              .ttl(ttl)
              .deviceType(deviceType)
              .confidence(confidence)
              .build());
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

  /**
   * Core classifier: weighs signals and returns the most likely device type.
   * Populates {@code scoresOut} with the final per-type scores so the caller
   * can compute a margin-based confidence.
   */
  private String scoreAndClassify(
      String ip, HostProfile p, Integer ttl, String ouiHint, Map<String, Integer> scoresOut) {

    Map<String, Integer> scores = scoresOut;
    scores.put(ROUTER, 0);
    scores.put(MOBILE, 0);
    scores.put(LAPTOP_DESKTOP, 0);
    scores.put(SERVER, 0);
    scores.put(IOT, 0);

    // --- Signal 1: OUI hint ---
    if (ouiHint != null) {
      scores.merge(ouiHint, 40, Integer::sum);
    }

    // --- Signal 2: TTL fingerprinting ---
    if (ttl != null) {
      int normalised = normaliseTtl(ttl);
      if (normalised == 128) {
        // Windows → laptop/desktop
        scores.merge(LAPTOP_DESKTOP, 30, Integer::sum);
      } else if (normalised == 64) {
        // Linux/Unix/Android/iOS — could be server, mobile, router
        scores.merge(SERVER, 10, Integer::sum);
        scores.merge(MOBILE, 10, Integer::sum);
        scores.merge(ROUTER, 10, Integer::sum);
      } else if (normalised == 255) {
        // Cisco/network devices
        scores.merge(ROUTER, 30, Integer::sum);
      }
    }

    // --- Signal 3: nDPI app profile ---
    for (String app : p.apps) {
      if (MOBILE_APPS.contains(app)) scores.merge(MOBILE, 20, Integer::sum);
      if (DESKTOP_APPS.contains(app)) scores.merge(LAPTOP_DESKTOP, 20, Integer::sum);
      if (SERVER_APPS.contains(app)) scores.merge(SERVER, 20, Integer::sum);
    }
    for (String cat : p.categories) {
      if (IOT_CATEGORIES.contains(cat)) scores.merge(IOT, 15, Integer::sum);
      if ("Web".equals(cat) || "Media".equals(cat)) scores.merge(LAPTOP_DESKTOP, 5, Integer::sum);
    }

    // --- Signal 4: Traffic patterns ---
    // High peer count → likely router
    if (p.peers.size() >= 15) {
      scores.merge(ROUTER, 35, Integer::sum);
    } else if (p.peers.size() >= 8) {
      scores.merge(ROUTER, 15, Integer::sum);
    }

    // Only receives on well-known ports, never initiates → server
    boolean receivesOnWellKnown =
        p.receivedOnPorts.stream().anyMatch(port -> port < 1024);
    boolean neverInitiates = p.initiatedCount == 0;
    if (neverInitiates && receivesOnWellKnown) {
      scores.merge(SERVER, 35, Integer::sum);
    } else if (neverInitiates) {
      scores.merge(SERVER, 15, Integer::sum);
    }

    // Low variety + low volume → IoT
    if (p.apps.size() <= 2 && p.conversationCount <= 5 && p.totalPackets < 200) {
      scores.merge(IOT, 20, Integer::sum);
    }

    // Mostly initiates traffic (client-like) with varied apps → mobile/laptop
    double initiateRatio =
        p.conversationCount > 0 ? (double) p.initiatedCount / p.conversationCount : 0;
    if (initiateRatio > 0.7 && p.apps.size() > 3) {
      scores.merge(MOBILE, 10, Integer::sum);
      scores.merge(LAPTOP_DESKTOP, 10, Integer::sum);
    }

    // DNS/NTP only → router/server
    boolean onlyInfraApps =
        !p.apps.isEmpty()
            && p.apps.stream()
                .allMatch(a -> a.equalsIgnoreCase("DNS") || a.equalsIgnoreCase("NTP"));
    if (onlyInfraApps) {
      scores.merge(ROUTER, 20, Integer::sum);
      scores.merge(SERVER, 15, Integer::sum);
    }

    return scores.entrySet().stream()
        .max(Map.Entry.comparingByValue())
        .filter(e -> e.getValue() > 0)
        .map(Map.Entry::getKey)
        .orElse(UNKNOWN);
  }

  /**
   * Confidence based on the score margin between the winning type and the
   * second-best type. A large margin means the classification is unambiguous;
   * a small margin means the signals are conflicted.
   *
   * <p>Scale: margin ≥ 60 → 100 %, scaled linearly down to 0 % at margin = 0.
   */
  private int computeConfidence(Map<String, Integer> scores) {
    List<Integer> sorted = scores.values().stream()
        .sorted(Comparator.reverseOrder())
        .toList();
    if (sorted.isEmpty() || sorted.get(0) == 0) return 0;
    int best   = sorted.get(0);
    int second = sorted.size() > 1 ? sorted.get(1) : 0;
    int margin = best - second;
    // Clamp margin to [0, 60] and scale to [0, 100]
    return Math.min(100, (int) Math.round(margin * 100.0 / 60.0));
  }

  /**
   * Normalises an observed IP TTL to the most likely initial value (64, 128, or 255).
   * The initial TTL decrements by 1 per hop, so we pick the nearest standard value that
   * is >= the observed value.
   */
  private int normaliseTtl(int ttl) {
    if (ttl > 128) return 255;
    if (ttl > 64) return 128;
    return 64;
  }

  // -------------------------------------------------------------------------
  // Per-host profile accumulator (internal, not persisted)
  // -------------------------------------------------------------------------

  private static class HostProfile {
    long totalBytes = 0;
    long totalPackets = 0;
    int conversationCount = 0;
    int initiatedCount = 0;
    Set<String> apps = new LinkedHashSet<>();
    Set<String> categories = new LinkedHashSet<>();
    Set<Integer> dstPorts = new LinkedHashSet<>();
    Set<Integer> receivedOnPorts = new LinkedHashSet<>();
    Set<String> peers = new LinkedHashSet<>();
  }
}
