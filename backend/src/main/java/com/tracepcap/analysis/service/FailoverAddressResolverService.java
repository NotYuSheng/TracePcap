package com.tracepcap.analysis.service;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Finds the virtual addresses of router failover pairs (#918 item 2): a VRRP or HSRP virtual IP is
 * shared by two or more routers, so it isn't a device of its own and shouldn't be classified as one.
 *
 * <p>Two kinds of evidence, both exact:
 *
 * <ul>
 *   <li><b>Adverts.</b> VRRP (IP protocol 112) names its virtual addresses ({@code vrrp.ip_addr}),
 *       HSRP v1/v2 (UDP 1985) its virtual IP; the routers sending them are the members. CARP shares
 *       protocol 112 but doesn't carry the address, so it's found the second way.
 *   <li><b>Virtual-router MACs.</b> IANA's VRRP/CARP MAC {@code 00:00:5e:00:01:xx}, and Cisco's HSRP
 *       MACs {@code 00:00:0c:07:ac:xx} (v1) and {@code 00:00:0c:9f:fx:xx} (v2). An IP answered by
 *       one of these is a virtual address. See {@link #isVirtualRouterMac}.
 * </ul>
 *
 * Reads only the capture, so it runs in the tool stage with no database connection. Never throws.
 */
@Slf4j
@Service
public class FailoverAddressResolverService {

  /** A virtual address: which protocol, and the routers seen advertising it (may be empty). */
  public record VirtualAddress(String ip, String protocol, Set<String> members) {}

  private static final Pattern VRRP_MAC = Pattern.compile("(?i)^00:00:5e:00:01:[0-9a-f]{2}$");
  private static final Pattern HSRP1_MAC = Pattern.compile("(?i)^00:00:0c:07:ac:[0-9a-f]{2}$");
  private static final Pattern HSRP2_MAC = Pattern.compile("(?i)^00:00:0c:9f:f[0-9a-f]:[0-9a-f]{2}$");

  /** The protocol a virtual-router MAC belongs to, or null if it isn't one. */
  public static String virtualRouterProtocol(String mac) {
    if (mac == null) return null;
    if (VRRP_MAC.matcher(mac).matches()) return "VRRP/CARP";
    if (HSRP1_MAC.matcher(mac).matches() || HSRP2_MAC.matcher(mac).matches()) return "HSRP";
    return null;
  }

  public static boolean isVirtualRouterMac(String mac) {
    return virtualRouterProtocol(mac) != null;
  }

  /** The virtual addresses the capture's adverts name, by IP. */
  public Map<String, VirtualAddress> resolve(File pcapFile) {
    Map<String, String> protocolByIp = new LinkedHashMap<>();
    Map<String, Set<String>> membersByIp = new LinkedHashMap<>();
    ProcessBuilder pb =
        new ProcessBuilder(
            "tshark",
            "-r",
            pcapFile.getAbsolutePath(),
            "-Y",
            // HSRPv2 is dissected by "hsrp" too (its fields are hsrp2.*); "hsrp2" isn't a protocol
            // name, and an invalid filter makes tshark reject the whole pass.
            "vrrp || hsrp",
            "-T",
            "fields",
            "-E",
            "separator=|",
            "-E",
            "occurrence=a",
            "-E",
            "aggregator=,",
            "-e",
            "ip.src",
            "-e",
            "vrrp.ip_addr",
            "-e",
            "hsrp.virt_ip",
            "-e",
            "hsrp2.virt_ip");
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
                    String[] f = line.split("\\|", -1);
                    if (f.length < 4) continue;
                    String src = f[0].split(",")[0].trim();
                    record(f[1], "VRRP", src, protocolByIp, membersByIp);
                    record(f[2], "HSRP", src, protocolByIp, membersByIp);
                    record(f[3], "HSRP", src, protocolByIp, membersByIp);
                  }
                } catch (Exception ignored) {
                  // best-effort
                }
              });

      if (!process.waitFor(2, TimeUnit.MINUTES)) {
        log.warn("Failover address resolution timed out; returning partial results");
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
      log.warn("Failover address resolution failed: {}", e.getMessage());
    } finally {
      if (process != null) process.destroyForcibly();
      if (ioExecutor != null) ioExecutor.shutdownNow();
    }

    Map<String, VirtualAddress> out = new LinkedHashMap<>();
    protocolByIp.forEach((ip, proto) -> out.put(ip, new VirtualAddress(ip, proto, membersByIp.get(ip))));
    if (!out.isEmpty()) log.info("Found {} failover virtual address(es): {}", out.size(), out.keySet());
    return out;
  }

  private static void record(
      String field, String protocol, String src, Map<String, String> protocolByIp, Map<String, Set<String>> membersByIp) {
    if (field == null || field.isBlank()) return;
    for (String vip : field.split(",")) {
      String ip = vip.trim();
      if (ip.isEmpty() || ip.equals("0.0.0.0")) continue;
      protocolByIp.putIfAbsent(ip, protocol);
      Set<String> members = membersByIp.computeIfAbsent(ip, k -> new TreeSet<>());
      if (!src.isEmpty() && !src.equals(ip)) members.add(src);
    }
  }

  /** For logging and tests: the members as a list. */
  static List<String> members(VirtualAddress v) {
    return v.members() == null ? List.of() : new ArrayList<>(v.members());
  }
}
