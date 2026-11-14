package com.tracepcap.analysis.service;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Finds DHCP leases (#918 item 3): which client MAC was given, or asked for, which address and
 * when. A different MAC on the same address later in the capture is evidence that the address
 * passed to another device.
 *
 * <ul>
 *   <li><b>ACK</b> (type 5): the server hands {@code yiaddr} (or confirms {@code ciaddr}) to
 *       {@code chaddr}.
 *   <li><b>REQUEST</b> (type 3): the client asks for an address (option 50, or {@code ciaddr} when
 *       renewing) and usually names itself (option 12).
 * </ul>
 *
 * Reads only the capture, so it runs in the tool stage with no database connection. Never throws.
 */
@Slf4j
@Service
public class DhcpLeaseResolverService {

  /**
   * One (ip, client MAC) lease with its first and last time and the hostname asked under, plus the
   * client's DHCP fingerprint (#918 slice 4b): the options it asked for, in order (option 55), and
   * its vendor class (option 60). The fingerprint names the client's OS and often its model, and
   * stays the same when a phone changes its private MAC.
   */
  public record Lease(
      String ip, String mac, String hostname, LocalDateTime firstSeen, LocalDateTime lastSeen,
      String fingerprint, String vendorClass, Network network) {

    public Lease(String ip, String mac, String hostname, LocalDateTime firstSeen, LocalDateTime lastSeen) {
      this(ip, mac, hostname, firstSeen, lastSeen, null, null, null);
    }

    public Lease(
        String ip, String mac, String hostname, LocalDateTime firstSeen, LocalDateTime lastSeen,
        String fingerprint, String vendorClass) {
      this(ip, mac, hostname, firstSeen, lastSeen, fingerprint, vendorClass, null);
    }
  }

  /**
   * Which network the lease came from (#462), from the server's ACK: the server's MAC and
   * identifier (option 54), the router (3), domain (15), lease time in seconds (51), subnet mask (1),
   * and the 802.1Q VLAN the ACK was tagged with. Two networks using one range differ here.
   */
  public record Network(
      String serverMac, String serverId, String router, String domain, Long leaseSeconds,
      String subnetMask, Integer vlanId) {}

  public List<Lease> resolve(File pcapFile) {
    Map<String, Lease> leases = new LinkedHashMap<>();
    ProcessBuilder pb =
        new ProcessBuilder(
            "tshark",
            "-r",
            pcapFile.getAbsolutePath(),
            "-Y",
            "dhcp.option.dhcp == 3 || dhcp.option.dhcp == 5",
            "-T",
            "fields",
            "-E",
            "separator=|",
            "-E",
            // Every occurrence, so option 55's list comes through whole; the single-valued fields
            // take their first.
            "occurrence=a",
            "-E",
            "aggregator=;",
            "-e",
            "frame.time_epoch",
            "-e",
            "dhcp.option.dhcp",
            "-e",
            "dhcp.ip.your",
            "-e",
            "dhcp.ip.client",
            "-e",
            "dhcp.option.requested_ip_address",
            "-e",
            "dhcp.hw.mac_addr",
            "-e",
            "dhcp.option.hostname",
            "-e",
            "dhcp.option.request_list_item",
            "-e",
            "dhcp.option.vendor_class_id",
            "-e",
            "eth.src",
            "-e",
            "dhcp.option.dhcp_server_id",
            "-e",
            "dhcp.option.router",
            "-e",
            "dhcp.option.domain_name",
            "-e",
            "dhcp.option.ip_address_lease_time",
            "-e",
            "dhcp.option.subnet_mask",
            "-e",
            "vlan.id");
    pb.redirectErrorStream(false);

    Process process = null;
    ExecutorService ioExecutor = null;
    try {
      process = pb.start();
      final Process proc = process;
      Thread stderrThread =
          new Thread(
              () -> {
                try (BufferedReader err =
                    new BufferedReader(new InputStreamReader(proc.getErrorStream(), StandardCharsets.UTF_8))) {
                  while (err.readLine() != null) {
                    // discard
                  }
                } catch (Exception ignored) {
                  // best-effort
                }
              });
      stderrThread.setDaemon(true);
      stderrThread.start();

      ioExecutor = Executors.newSingleThreadExecutor();
      Future<?> stdoutTask =
          ioExecutor.submit(
              () -> {
                try (BufferedReader reader =
                    new BufferedReader(new InputStreamReader(proc.getInputStream(), StandardCharsets.UTF_8))) {
                  String line;
                  while ((line = reader.readLine()) != null) {
                    synchronized (leases) {
                      parseRow(line.split("\\|", -1), leases);
                    }
                  }
                } catch (Exception ignored) {
                  // best-effort
                }
              });

      if (!process.waitFor(2, TimeUnit.MINUTES)) {
        log.warn("DHCP lease resolution timed out; returning partial results");
      } else {
        try {
          stdoutTask.get(5, TimeUnit.SECONDS);
        } catch (Exception ignored) {
          // best-effort
        }
      }
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    } catch (Exception e) {
      log.warn("DHCP lease resolution failed: {}", e.getMessage());
    } finally {
      if (process != null) process.destroyForcibly();
      if (ioExecutor != null) ioExecutor.shutdownNow();
    }
    synchronized (leases) {
      if (!leases.isEmpty()) log.info("Found {} DHCP lease(s)", leases.size());
      return new ArrayList<>(leases.values());
    }
  }

  /**
   * Folds one tshark row into {@code leases}. Fields: epoch, message type, yiaddr, ciaddr,
   * requested address, chaddr, hostname.
   */
  static void parseRow(String[] f, Map<String, Lease> leases) {
    if (f.length < 7) return;
    // Fields 0–6 hold one value each; with every occurrence on, keep the first.
    String fingerprint = f.length > 7 && !f[7].isBlank() ? f[7].trim().replace(';', ',') : null;
    if (fingerprint != null && fingerprint.length() > 255) fingerprint = fingerprint.substring(0, 255);
    String vendorClass = f.length > 8 && !f[8].isBlank() ? first(f[8]) : null;
    if (vendorClass != null && vendorClass.length() > 255) vendorClass = vendorClass.substring(0, 255);
    f = java.util.Arrays.stream(f).map(DhcpLeaseResolverService::first).toArray(String[]::new);
    // The network the server's ACK names (#462); a REQUEST's eth.src is the client, so ACKs only.
    Network network = "5".equals(f[1].trim()) && f.length > 15 ? network(f) : null;
    LocalDateTime at;
    try {
      double epoch = Double.parseDouble(f[0].trim());
      at = LocalDateTime.ofInstant(Instant.ofEpochMilli((long) (epoch * 1000)), ZoneId.systemDefault());
    } catch (NumberFormatException e) {
      return;
    }
    String type = f[1].trim();
    String ip =
        switch (type) {
          case "5" -> usable(f[2]) ? f[2].trim() : usable(f[3]) ? f[3].trim() : null;
          case "3" -> usable(f[4]) ? f[4].trim() : usable(f[3]) ? f[3].trim() : null;
          default -> null;
        };
    String mac = f[5].trim().toLowerCase();
    if (ip == null || ip.length() > 45 || mac.isEmpty() || mac.length() > 50) return;
    String hostname = f[6].trim();
    if (hostname.isEmpty()) hostname = null;
    else if (hostname.length() > 255) hostname = hostname.substring(0, 255);

    String key = ip + "|" + mac;
    Lease prev = leases.get(key);
    if (prev == null) {
      leases.put(key, new Lease(ip, mac, hostname, at, at, fingerprint, vendorClass, network));
    } else {
      leases.put(
          key,
          new Lease(
              ip,
              mac,
              hostname != null ? hostname : prev.hostname(),
              at.isBefore(prev.firstSeen()) ? at : prev.firstSeen(),
              at.isAfter(prev.lastSeen()) ? at : prev.lastSeen(),
              fingerprint != null ? fingerprint : prev.fingerprint(),
              vendorClass != null ? vendorClass : prev.vendorClass(),
              network != null ? network : prev.network()));
    }
  }

  private static Network network(String[] f) {
    String serverMac = blank(f[9]) ? null : f[9].trim().toLowerCase();
    Long lease = null;
    try {
      if (!blank(f[13])) lease = Long.parseLong(f[13].trim());
    } catch (NumberFormatException ignored) {
      // tshark may print the lease as text; leave it unknown
    }
    Integer vlan = null;
    try {
      if (f.length > 15 && !blank(f[15])) vlan = Integer.parseInt(f[15].trim());
    } catch (NumberFormatException ignored) {
      // not a VLAN id
    }
    Network n =
        new Network(serverMac, cut(f[10], 45), cut(f[11], 45), cut(f[12], 255), lease,
            f.length > 14 ? cut(f[14], 45) : null, vlan);
    return n.serverMac() == null && n.serverId() == null && n.vlanId() == null ? null : n;
  }

  private static boolean blank(String s) {
    return s == null || s.isBlank();
  }

  private static String cut(String s, int max) {
    if (blank(s)) return null;
    String t = s.trim();
    return t.length() > max ? t.substring(0, max) : t;
  }

  /** The first of an aggregated field's values. */
  private static String first(String field) {
    if (field == null) return "";
    int i = field.indexOf(';');
    return (i < 0 ? field : field.substring(0, i)).trim();
  }

  private static boolean usable(String ip) {
    if (ip == null) return false;
    String s = ip.trim();
    return !s.isEmpty() && !s.equals("0.0.0.0");
  }
}
