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

  /** One (ip, client MAC) lease with its first and last time and the hostname asked under. */
  public record Lease(String ip, String mac, String hostname, LocalDateTime firstSeen, LocalDateTime lastSeen) {}

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
            "occurrence=f",
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
            "dhcp.option.hostname");
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
      leases.put(key, new Lease(ip, mac, hostname, at, at));
    } else {
      leases.put(
          key,
          new Lease(
              ip,
              mac,
              hostname != null ? hostname : prev.hostname(),
              at.isBefore(prev.firstSeen()) ? at : prev.firstSeen(),
              at.isAfter(prev.lastSeen()) ? at : prev.lastSeen()));
    }
  }

  private static boolean usable(String ip) {
    if (ip == null) return false;
    String s = ip.trim();
    return !s.isEmpty() && !s.equals("0.0.0.0");
  }
}
