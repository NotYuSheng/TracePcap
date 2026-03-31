package com.tracepcap.analysis.service;

import com.tracepcap.analysis.entity.HostClassificationEntity;
import com.tracepcap.file.entity.FileEntity;
import java.util.*;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
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
  // OUI vendor prefix → device-type hint  (first 3 octets, colon-separated, lower-case)
  // -------------------------------------------------------------------------

  private static final Map<String, String> OUI_VENDOR = new LinkedHashMap<>();
  private static final Map<String, String> OUI_DEVICE_HINT = new LinkedHashMap<>();

  static {
    // Apple
    String[] appleOuis = {
      "00:03:93", "00:0a:27", "00:0a:95", "00:0d:93", "00:11:24", "00:14:51", "00:16:cb",
      "00:17:f2", "00:19:e3", "00:1b:63", "00:1c:b3", "00:1e:52", "00:1e:c2", "00:1f:5b",
      "00:1f:f3", "00:21:e9", "00:22:41", "00:23:12", "00:23:32", "00:23:6c", "00:23:df",
      "00:24:36", "00:25:4b", "00:25:bc", "00:26:08", "00:26:4a", "00:26:b9", "00:26:bb",
      "00:3e:e1", "00:50:e4", "00:56:cd", "04:0c:ce", "04:15:52", "04:26:65", "04:48:9a",
      "04:54:53", "04:69:f8", "04:e5:36", "08:66:98", "08:6d:41", "08:70:45", "08:74:02",
      "0c:3e:9f", "0c:74:c2", "10:1c:0c", "10:40:f3", "10:9a:dd", "10:dd:b1", "14:10:9f",
      "14:8f:c6", "18:65:90", "18:9e:fc", "18:af:61", "1c:36:bb", "1c:91:48", "20:78:f0",
      "24:1e:eb", "24:a0:74", "28:37:37", "28:6a:b8", "2c:f0:ee", "30:35:ad", "34:15:9e",
      "34:36:3b", "38:0f:4a", "3c:15:c2", "3c:d0:f8", "40:3c:fc", "44:2a:60", "44:d8:84",
      "48:43:7c", "4c:57:ca", "50:ea:d6", "54:26:96", "58:55:ca", "5c:f7:e6", "60:03:08",
      "60:c5:47", "60:fb:42", "64:76:ba", "64:a3:cb", "68:96:7b", "6c:72:e7", "70:11:24",
      "70:3e:ac", "74:e2:f5", "78:7b:8a", "78:ca:39", "7c:11:be", "7c:c3:a1", "80:82:23",
      "80:be:05", "84:38:35", "84:78:8b", "88:19:08", "88:53:95", "8c:7b:9d", "90:27:e4",
      "90:60:f1", "90:72:40", "94:bf:2d", "98:d6:bb", "9c:04:eb", "9c:20:7b", "a4:5e:60",
      "a8:51:ab", "a8:60:b6", "ac:1f:74", "b0:34:95", "b4:18:d1", "b8:09:8a", "b8:78:2e",
      "bc:92:6b", "c0:ce:cd", "c4:2c:03", "c8:2a:14", "c8:d0:83", "cc:25:ef", "d0:03:4b",
      "d4:61:9d", "d8:30:62", "d8:8f:76", "dc:2b:61", "e0:ac:cb", "e4:ce:8f", "e8:04:0b",
      "ec:35:86", "f0:18:98", "f4:37:b7", "f8:1e:df", "fc:25:3f"
    };
    for (String oui : appleOuis) {
      OUI_VENDOR.put(oui, "Apple");
      OUI_DEVICE_HINT.put(oui, MOBILE); // refined later by TTL / app profile
    }

    // Samsung
    String[] samsungOuis = {
      "00:02:78", "00:07:ab", "00:12:47", "00:15:b9", "00:16:32", "00:17:c9", "00:1a:8a",
      "00:1b:98", "00:1d:25", "00:1e:7d", "00:1f:cc", "00:21:19", "00:23:99", "00:24:54",
      "00:26:37", "00:e0:64", "04:18:d6", "08:08:c2", "08:37:3d", "08:ec:f5", "0c:14:20",
      "0c:71:5d", "10:1d:c0", "14:49:e0", "14:a3:64", "18:3a:2d", "1c:62:b8", "20:13:e0",
      "24:4b:81", "28:ba:b5", "2c:ae:2b", "30:07:4d", "34:31:11", "38:01:97", "38:2d:e8",
      "3c:5a:37", "40:0e:85", "44:4e:1a", "48:44:f7", "4c:3c:16", "50:01:bb", "50:32:75",
      "54:92:be", "58:ef:68", "5c:2e:59", "60:d0:a9", "64:b3:10", "68:eb:ae", "6c:2f:2c",
      "70:f9:27", "74:45:8a", "78:40:e4", "7c:0b:c6", "80:57:19", "84:11:9e", "88:32:9b",
      "8c:71:f8", "90:18:7c", "94:35:0a", "98:52:b1", "9c:02:98", "a0:07:98", "a4:eb:d3",
      "a8:04:60", "ac:5f:3e", "b0:72:bf", "b4:07:f9", "b8:57:d8", "bc:14:85", "c0:bd:d1",
      "c4:42:02", "c8:ba:94", "cc:07:ab", "d0:22:be", "d4:87:d8", "d8:57:ef", "dc:71:96",
      "e0:99:71", "e4:40:e2", "e8:50:8b", "ec:1f:72", "f0:08:f1", "f4:42:8f", "f8:04:2e"
    };
    for (String oui : samsungOuis) {
      OUI_VENDOR.put(oui, "Samsung");
      OUI_DEVICE_HINT.put(oui, MOBILE);
    }

    // Cisco
    String[] ciscoOuis = {
      "00:00:0c", "00:01:42", "00:01:43", "00:01:63", "00:01:64", "00:01:96", "00:01:97",
      "00:01:c7", "00:02:16", "00:02:17", "00:02:3d", "00:02:4a", "00:02:4b", "00:02:7d",
      "00:02:b9", "00:03:6b", "00:03:e3", "00:03:fd", "00:04:6d", "00:04:9a", "00:04:dd",
      "00:05:00", "00:05:dc", "00:05:dd", "00:06:28", "00:06:52", "00:06:c1", "00:07:0d",
      "00:07:50", "00:07:85", "00:07:b3", "00:07:eb", "00:08:20", "00:08:a3", "00:08:e2",
      "00:09:11", "00:09:43", "00:09:7b", "00:09:b0", "00:09:b1", "00:09:e8", "00:0a:41",
      "00:0a:42", "00:0a:8a", "00:0a:f3", "00:0b:45", "00:0b:46", "00:0b:be", "00:0b:fd",
      "00:0c:85", "00:0c:ce", "00:0d:28", "00:0d:29", "00:0d:bc", "00:0d:bd", "00:0e:08",
      "00:0e:38", "00:0e:83", "00:0e:84", "00:0f:23", "00:0f:24", "00:0f:8f", "00:0f:90",
      "00:10:07", "00:10:0d", "00:10:11", "00:10:14", "00:10:29", "00:10:2f", "00:10:54",
      "00:10:79", "00:10:7b", "00:10:a6", "00:10:f6", "00:11:5c", "00:11:92", "00:11:bc",
      "00:12:00", "00:12:01", "00:12:7f", "00:12:80", "00:12:d9", "00:13:10", "00:13:19",
      "00:13:1a", "00:13:5f", "00:13:60", "00:13:c3", "00:13:c4", "00:14:1b", "00:14:1c",
      "00:14:69", "00:14:6a", "00:14:a9", "00:14:bf", "00:15:2b", "00:15:2c", "00:15:62",
      "00:15:63", "00:15:c6", "00:15:c7", "00:16:46", "00:16:47", "00:16:9c", "00:16:9d",
      "00:17:0e", "00:17:0f", "00:17:5a", "00:17:5b", "00:17:94", "00:17:95", "00:17:df",
      "00:18:18", "00:18:19", "00:18:68", "00:18:73", "00:18:b9", "00:18:ba", "00:19:06",
      "00:19:07", "00:19:2f", "00:19:55", "00:19:56", "00:19:aa", "00:19:ab", "00:1a:2f",
      "00:1a:30", "00:1a:6c", "00:1a:6d", "00:1a:a1", "00:1a:a2", "00:1b:0c", "00:1b:0d",
      "00:1b:53", "00:1b:54", "00:1b:8f", "00:1b:d4", "00:1c:0e", "00:1c:0f", "00:1c:57",
      "00:1c:58", "00:1c:f6", "00:1d:45", "00:1d:46", "00:1d:70", "00:1d:a1", "00:1d:a2",
      "00:1e:49", "00:1e:4a", "00:1e:be", "00:1e:bf", "00:1e:f6", "00:1e:f7", "00:1f:26",
      "00:1f:27", "00:1f:6c", "00:1f:6d", "00:1f:9d", "00:1f:9e", "00:21:1b", "00:21:1c",
      "00:21:55", "00:21:56", "00:21:a0", "00:21:a1", "00:22:0c", "00:22:0d", "00:22:55",
      "00:22:56", "00:22:90", "00:22:91", "00:22:bd", "00:22:be", "00:23:04", "00:23:05",
      "00:23:33", "00:23:34", "00:23:5e", "00:23:5f", "00:23:be", "00:23:bf", "00:23:eb",
      "00:24:13", "00:24:14", "00:24:97", "00:24:98", "00:24:c3", "00:24:c4", "00:24:f7",
      "00:25:45", "00:25:46", "00:25:83", "00:25:84", "00:25:b4", "00:25:b5", "00:26:0a",
      "00:26:0b", "00:26:ca", "00:26:cb", "00:26:99", "00:30:71", "00:30:80", "00:30:a3",
      "00:30:b6", "00:50:0f", "00:50:14", "00:50:3e", "00:50:50", "00:50:54", "00:50:73",
      "00:60:09", "00:60:2f", "00:60:3e", "00:60:47", "00:60:4f", "00:60:5c", "00:60:70",
      "00:60:83", "00:60:8c", "00:60:97", "00:70:82", "00:90:0c", "00:90:21", "00:90:2b",
      "00:90:5f", "00:90:6d", "00:90:86", "00:90:92", "00:90:ab", "00:90:b1", "00:90:d9",
      "00:90:f2", "00:b0:64", "00:d0:06", "00:d0:58", "00:d0:63", "00:d0:79", "00:d0:97",
      "00:d0:ba", "00:d0:bc", "00:d0:c0", "00:d0:d3", "00:d0:e4", "00:d0:ef", "00:d0:f8",
      "00:e0:14", "00:e0:1e", "00:e0:34", "00:e0:4f", "00:e0:8f", "00:e0:a3", "00:e0:b0",
      "00:e0:fe"
    };
    for (String oui : ciscoOuis) {
      OUI_VENDOR.put(oui, "Cisco");
      OUI_DEVICE_HINT.put(oui, ROUTER);
    }

    // Huawei
    String[] huaweiOuis = {
      "00:18:82", "00:1e:10", "00:25:9e", "00:34:fe", "00:46:4b", "00:9a:cd", "04:02:1f",
      "04:b0:e7", "04:c0:6f", "04:f9:38", "08:19:a6", "08:7a:4c", "08:9b:4b", "0c:37:dc",
      "0c:96:bf", "10:1b:54", "10:47:80", "14:a5:1a", "18:c5:8a", "1c:1d:67", "20:08:ed",
      "20:f3:a3", "28:6e:d4", "2c:ab:00", "30:45:96", "34:6b:d3", "38:37:8b", "3c:8c:93",
      "40:cb:a8", "44:55:b1", "44:a1:91", "48:00:31", "48:46:fb", "4c:1f:cc", "50:9f:27",
      "54:89:98", "58:60:5f", "5c:4c:a9", "5c:7d:5e", "60:de:44", "64:13:6c", "68:1d:ef",
      "6c:4b:90", "70:72:cf", "74:a0:63", "74:a5:28", "78:1d:ba", "7c:1c:f1", "80:fb:06",
      "84:be:52", "88:53:2e", "8c:34:fd", "8c:e1:17", "90:17:ac", "94:77:2b", "98:4f:ee",
      "9c:28:ef", "9c:74:1a", "a0:08:6f", "a0:86:c6", "a4:99:47", "a8:ca:7b", "ac:4e:91",
      "b0:e5:ed", "b4:15:13", "b4:cd:27", "b8:08:cf", "b8:bc:1b", "bc:25:e0", "bc:4c:c4",
      "c0:70:09", "c4:07:2f", "c4:f0:81", "c8:14:79", "cc:53:b5", "d0:27:88", "d4:6e:5c",
      "d4:f5:ef", "d8:49:0b", "dc:72:dc", "e0:19:54", "e4:68:a3", "e8:08:8b", "e8:cd:2d",
      "ec:23:3d", "f4:4c:7f", "f4:83:cd", "f8:01:13", "f8:4a:bf", "fc:48:ef"
    };
    for (String oui : huaweiOuis) {
      OUI_VENDOR.put(oui, "Huawei");
      OUI_DEVICE_HINT.put(oui, ROUTER); // could be phone too; refined by TTL
    }

    // TP-Link
    String[] tplinkOuis = {
      "00:27:19", "04:8d:38", "08:95:2a", "14:cc:20", "18:a6:f7", "1c:3b:f3", "20:dc:e6",
      "24:69:a5", "28:2c:02", "2c:d0:5a", "30:de:4b", "34:60:f9", "3c:84:6a", "40:16:7e",
      "44:94:fc", "4c:5e:0c", "50:fa:84", "54:67:51", "58:00:e3", "5c:89:9a", "60:32:b1",
      "60:a4:b7", "64:70:02", "68:ff:7b", "6c:19:8f", "6c:5a:b0", "70:4f:57", "74:ea:3a",
      "78:44:76", "7c:8b:ca", "80:35:c1", "84:16:f9", "88:1f:a1", "8c:21:0a", "90:f6:52",
      "94:d9:b3", "98:da:c4", "9c:a6:15", "a0:f3:c1", "a4:2b:b0", "a8:57:4e", "ac:84:c6",
      "b0:48:7a", "b0:95:75", "b4:b0:24", "b8:69:f4", "bc:46:99", "c4:6e:1f", "c8:0e:77",
      "cc:32:e5", "d8:0d:17", "d8:47:32", "dc:08:56", "dc:fe:18", "e0:05:c5", "e4:c3:2a",
      "e8:65:49", "ec:08:6b", "ec:17:2f", "f0:a7:31", "f4:f2:6d", "f8:1a:67", "fc:ec:da"
    };
    for (String oui : tplinkOuis) {
      OUI_VENDOR.put(oui, "TP-Link");
      OUI_DEVICE_HINT.put(oui, ROUTER);
    }

    // Dell
    String[] dellOuis = {
      "00:06:5b", "00:08:74", "00:0b:db", "00:0d:56", "00:0f:1f", "00:11:43", "00:12:3f",
      "00:13:72", "00:14:22", "00:15:c5", "00:16:f0", "00:18:8b", "00:19:b9", "00:1a:4b",
      "00:1c:23", "00:1d:09", "00:1e:4f", "00:1e:c9", "00:21:70", "00:22:19", "00:23:ae",
      "00:24:e8", "00:25:64", "00:26:b9", "00:27:13", "18:03:73", "18:66:da", "18:a9:9b",
      "1c:40:24", "24:b6:fd", "28:f1:0e", "2c:60:0c", "34:17:eb", "34:e6:d7", "3c:2c:30",
      "40:b0:76", "44:a8:42", "48:4d:7e", "4c:00:82", "54:9f:35", "5c:f9:dd", "60:eb:69",
      "6c:2b:59", "74:86:7a", "78:2b:cb", "7c:d1:c3", "80:18:44", "84:7b:eb", "8c:ec:4b",
      "90:b1:1c", "98:90:96", "9c:eb:e8", "a4:1f:72", "a4:ba:db", "b0:83:fe", "b8:ac:6f",
      "bc:30:5b", "c8:1f:66", "d4:ae:52", "d4:be:d9", "e0:db:55", "e4:f8:9c", "e8:b1:fc",
      "f0:1f:af", "f0:76:1c", "f4:8e:38", "f8:db:88", "f8:f1:27"
    };
    for (String oui : dellOuis) {
      OUI_VENDOR.put(oui, "Dell");
      OUI_DEVICE_HINT.put(oui, LAPTOP_DESKTOP);
    }

    // Raspberry Pi / common IoT vendors
    String[] rpiOuis = {
      "b8:27:eb", "dc:a6:32", "e4:5f:01", "28:cd:c1", "d8:3a:dd", "2c:cf:67"
    };
    for (String oui : rpiOuis) {
      OUI_VENDOR.put(oui, "Raspberry Pi");
      OUI_DEVICE_HINT.put(oui, IOT);
    }

    // Espressif (ESP8266/ESP32 — IoT microcontrollers)
    String[] espOuis = {
      "18:fe:34", "24:0a:c4", "2c:f4:32", "30:ae:a4", "3c:71:bf", "48:3f:da",
      "5c:cf:7f", "60:01:94", "68:c6:3a", "80:7d:3a", "84:0d:8e", "8c:aa:b5",
      "90:97:d5", "a0:20:a6", "a4:7b:9d", "b4:e6:2d", "bc:dd:c2", "cc:50:e3",
      "d8:bc:38", "dc:4f:22", "e8:db:84", "ec:fa:bc", "f0:08:d1", "f4:cf:a2"
    };
    for (String oui : espOuis) {
      OUI_VENDOR.put(oui, "Espressif");
      OUI_DEVICE_HINT.put(oui, IOT);
    }

    // Intel (laptops / desktops)
    String[] intelOuis = {
      "00:02:b3", "00:03:47", "00:04:23", "00:07:e9", "00:08:a0", "00:0c:f1", "00:0e:0c",
      "00:0e:35", "00:11:11", "00:12:f0", "00:13:02", "00:13:20", "00:13:ce", "00:13:e8",
      "00:15:00", "00:15:17", "00:16:6f", "00:16:76", "00:16:ea", "00:16:eb", "00:18:de",
      "00:19:d1", "00:19:d2", "00:1b:21", "00:1b:77", "00:1c:c0", "00:1d:e0", "00:1e:64",
      "00:1e:67", "00:1f:3b", "00:1f:3c", "00:21:6a", "00:21:d8", "00:22:fa", "00:22:fb",
      "00:23:14", "00:24:d6", "00:24:d7", "00:25:22", "00:26:c6", "00:26:c7", "00:27:10",
      "18:03:73", "40:25:c2", "44:85:00", "48:51:b7", "50:7b:9d", "54:27:1e", "54:8b:3d",
      "58:6a:b1", "60:67:20", "60:f8:1d", "64:00:6a", "68:05:ca", "68:17:29", "6c:88:14",
      "70:5a:0f", "78:92:9c", "7c:5c:f8", "80:19:34", "84:3a:4b", "88:53:2e", "8c:70:5a",
      "90:2b:34", "94:65:9c", "98:4f:ee", "9c:4e:36", "a0:a8:cd", "a4:c3:f0", "a8:7e:ea",
      "ac:7b:a1", "b0:c0:90", "b4:6b:fc", "b8:ae:ed", "bc:77:37", "c0:3f:d5", "c4:8b:ef",
      "c8:5b:76", "cc:3d:82", "d0:57:7b", "d4:3d:7e", "d8:fc:93", "dc:53:60", "e0:06:e6",
      "e4:b3:18", "e8:11:32", "ec:55:f9", "f0:de:f1", "f4:06:69", "f8:16:54", "fc:f8:ae"
    };
    for (String oui : intelOuis) {
      OUI_VENDOR.put(oui, "Intel");
      OUI_DEVICE_HINT.put(oui, LAPTOP_DESKTOP);
    }
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

      String deviceType = scoreAndClassify(ip, profile, ttl, ouiHint);
      int confidence = computeConfidence(profile, ttl, ouiHint, mac);

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
    return oui != null ? OUI_VENDOR.getOrDefault(oui, null) : null;
  }

  private String resolveOuiHint(String mac) {
    String oui = ouiKey(mac);
    return oui != null ? OUI_DEVICE_HINT.get(oui) : null;
  }

  private String ouiKey(String mac) {
    if (mac == null || mac.length() < 8) return null;
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
   */
  private String scoreAndClassify(
      String ip, HostProfile p, Integer ttl, String ouiHint) {

    Map<String, Integer> scores = new HashMap<>();
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
   * Confidence = number of distinct signals that agreed, scaled to 0–100.
   */
  private int computeConfidence(HostProfile p, Integer ttl, String ouiHint, String mac) {
    int signals = 0;
    if (ouiHint != null) signals++;
    if (ttl != null) signals++;
    if (!p.apps.isEmpty()) signals++;
    if (p.conversationCount >= 3) signals++; // enough traffic data
    // Max 4 signals → scale to 100
    return Math.min(100, signals * 25);
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
