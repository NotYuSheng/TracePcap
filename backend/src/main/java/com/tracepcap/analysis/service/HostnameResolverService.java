package com.tracepcap.analysis.service;

import com.tracepcap.common.net.TsharkAddressFields;
import com.tracepcap.common.net.IpLocality;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Resolves passively-observed hostnames for hosts in a PCAP capture.
 *
 * <p>Unlike the nDPI Hostname/SNI field (which records the <em>server</em> name a client connected
 * to), this service extracts names that identify the local hosts themselves, from four sources:
 *
 * <ul>
 *   <li><b>DHCP option 12</b> — the hostname a client advertises in its DHCP Request.
 *   <li><b>mDNS</b> — {@code *.local} names announced in multicast DNS A/AAAA responses.
 *   <li><b>NBNS</b> — NetBIOS names from name-service registrations/responses.
 *   <li><b>Reverse DNS</b> — PTR responses mapping an IP back to a name.
 * </ul>
 *
 * <p>A single host may be named by several sources; the most authoritative for the host's own
 * identity wins — but winner-picking no longer happens here (#512 slice 4): this extractor
 * records every claim it sees, conflict-preserving, and {@link HostnameAdjudicator} picks the
 * display winner from the persisted claims. Runs as a single read-only tshark pass and never
 * throws — on any failure it returns whatever was collected so far (possibly empty).
 */
@Slf4j
@Service
public class HostnameResolverService {

  public static final String SOURCE_REVERSE_DNS = "reverse_dns";
  public static final String SOURCE_MDNS = "mdns";
  public static final String SOURCE_NBNS = "nbns";
  public static final String SOURCE_DHCP = "dhcp";
  /**
   * The workstation name a client gives when it signs in with NTLM (#1234): the host naming
   * itself, like NBNS. Sent on Windows file-share and intranet sign-ins even when no account is
   * (anonymous sessions still carry it).
   */
  public static final String SOURCE_NTLM = "ntlm";
  public static final String SOURCE_MANUAL = "manual";

  private static final int HOSTNAME_MAX_LENGTH = 255;

  /** A discovered hostname together with how it was found. */
  public record ResolvedHostname(String hostname, String source) {}

  /** One raw claim: {@code source} asserted that {@code ip} is named {@code hostname}. */
  public record Claim(String ip, String hostname, String source) {}

  /** The row layout {@link #parseRow} reads; an IPv6 packet's source is folded into ip.src (#1357). */
  static final String[] FIELDS = {
    "_ws.col.Protocol", "ip.src", "dhcp.option.hostname", "dhcp.option.requested_ip_address", "dns.resp.name", "dns.a", "dns.aaaa", "dns.ptr.domain_name", "dns.qry.name", "nbns.name", "nbns.addr", "ntlmssp.auth.hostname"
  };

  /**
   * Scans the capture and returns a map of IP → resolved hostname for every host whose name could
   * be derived from DHCP, mDNS, NBNS or reverse DNS.
   */
  public List<Claim> resolve(File pcapFile) {
    // Concurrent: the stdout reader (background thread) writes while the main thread reads size().
    // Keyed by (ip, hostname, source) to dedupe repeats while preserving distinct claims.
    Map<Claim, Boolean> result = new ConcurrentHashMap<>();

    // Fields (pipe-separated, first occurrence only):
    //   0 _ws.col.Protocol  1 ip.src  2 dhcp.option.hostname
    //   3 dhcp.option.requested_ip_address  4 dns.resp.name  5 dns.a  6 dns.aaaa
    //   7 dns.ptr.domain_name  8 dns.qry.name  9 nbns.name  10 nbns.addr
    //   11 ntlmssp.auth.hostname
    ProcessBuilder pb =
        new ProcessBuilder(
            TsharkAddressFields.command(
                FIELDS,
            "tshark",
            "-r",
            pcapFile.getAbsolutePath(),
            "-Y",
            "dhcp.option.hostname || (mdns && dns.flags.response==1) || nbns.name"
                + " || (dns.flags.response==1 && dns.qry.type==12) || ntlmssp.auth.hostname",
            "-T",
            "fields",
            "-E",
            "separator=|",
            "-E",
            "occurrence=f"));
    pb.redirectErrorStream(false);

    Process process = null;
    ExecutorService ioExecutor = null;
    try {
      process = pb.start();
      final Process proc = process;

      // Drain stderr so it can't block stdout.
      Thread stderrThread =
          new Thread(
              () -> {
                try (BufferedReader err =
                    new BufferedReader(
                        new InputStreamReader(proc.getErrorStream(), StandardCharsets.UTF_8))) {
                  while (err.readLine() != null) {
                    // discard
                  }
                } catch (Exception ignored) {
                  // best-effort
                }
              });
      stderrThread.setDaemon(true);
      stderrThread.start();

      // Read stdout on a separate thread so a tshark that hangs while holding stdout open
      // can't block the waitFor timeout below indefinitely.
      ioExecutor = Executors.newSingleThreadExecutor();
      Future<?> stdoutTask =
          ioExecutor.submit(
              () -> {
                try (BufferedReader reader =
                    new BufferedReader(
                        new InputStreamReader(proc.getInputStream(), StandardCharsets.UTF_8))) {
                  String line;
                  while ((line = reader.readLine()) != null) {
                    if (!line.isEmpty()) parseRow(TsharkAddressFields.fold(line.split("\\|", -1), FIELDS), result);
                  }
                } catch (Exception ignored) {
                  // best-effort
                }
              });

      boolean finished = process.waitFor(2, TimeUnit.MINUTES);
      if (!finished) {
        log.warn("Hostname resolution timed out; returning {} partial result(s)", result.size());
      } else {
        int exit = process.exitValue();
        if (exit != 0) {
          log.warn("Hostname resolution: tshark exited with code {}; results may be partial", exit);
        }
        // Let the reader drain any output still buffered after the process exited.
        try {
          stdoutTask.get(5, TimeUnit.SECONDS);
        } catch (Exception ignored) {
          // best-effort
        }
      }
    } catch (InterruptedException e) {
      log.warn("Hostname resolution interrupted");
      Thread.currentThread().interrupt();
    } catch (Exception e) {
      log.warn("Hostname resolution failed: {}", e.getMessage());
    } finally {
      if (process != null) process.destroyForcibly();
      if (ioExecutor != null) ioExecutor.shutdownNow();
    }

    log.info("Collected {} hostname claim(s) from DHCP/mDNS/NBNS/NTLM/reverse-DNS", result.size());
    return new ArrayList<>(result.keySet());
  }

  // ── Row parsing ─────────────────────────────────────────────────────────────

  private void parseRow(String[] f, Map<Claim, Boolean> result) {
    if (f.length < 11) return;
    String proto = f[0].toUpperCase();

    // NTLM rides inside SMB, HTTP, LDAP..., so it's checked on its own, not by protocol column.
    // The sender of an AUTHENTICATE message is the client naming itself.
    if (f.length > 11 && !f[11].isBlank()) {
      String name = firstValue(f[11]);
      if (name != null && !"NULL".equals(name)) record(result, firstValue(f[1]), name, SOURCE_NTLM);
      return;
    }

    if (proto.contains("DHCP") || proto.contains("BOOTP")) {
      // option 12 hostname; IP is the requested address (option 50) or, failing that, the source.
      String ip = firstValue(f[3]);
      if (!IpLocality.isAssigned(ip)) ip = firstValue(f[1]);
      record(result, ip, f[2], SOURCE_DHCP);
    } else if (proto.equals("MDNS")) {
      String ip = firstValue(f[5]);
      if (ip == null) ip = firstValue(f[6]);
      String name = stripTrailingDot(f[4]);
      // Skip service-discovery records (e.g. "_spotify-connect._tcp.local"); keep host names.
      if (isPlausibleHostName(name)) record(result, ip, name, SOURCE_MDNS);
    } else if (proto.contains("NBNS")) {
      String ip = firstValue(f[10]);
      if (!IpLocality.isAssigned(ip)) ip = firstValue(f[1]);
      record(result, ip, cleanNetbiosName(f[9]), SOURCE_NBNS);
    } else if (proto.contains("DNS")) {
      // Reverse PTR: question is "<ip>.in-addr.arpa", answer is the name.
      String ip = arpaToIp(firstValue(f[8]));
      record(result, ip, stripTrailingDot(f[7]), SOURCE_REVERSE_DNS);
    }
  }

  /** Records one claim verbatim. No winner-picking here — that is the adjudicator's job. */
  private void record(Map<Claim, Boolean> result, String ip, String rawHostname, String source) {
    if (!IpLocality.isAssigned(ip)) return;
    String hostname = cleanHostname(rawHostname);
    if (hostname == null) return;
    result.putIfAbsent(new Claim(ip, hostname, source), Boolean.TRUE);
  }

  // ── Field helpers ────────────────────────────────────────────────────────────

  /** tshark may join multiple occurrences with ','; take the first non-blank token. */
  private String firstValue(String field) {
    if (field == null) return null;
    String trimmed = field.trim();
    if (trimmed.isEmpty()) return null;
    int comma = trimmed.indexOf(',');
    return comma >= 0 ? trimmed.substring(0, comma).trim() : trimmed;
  }

  private String cleanHostname(String raw) {
    if (raw == null) return null;
    String h = raw.trim();
    if (h.isEmpty()) return null;
    if (h.length() > HOSTNAME_MAX_LENGTH) h = h.substring(0, HOSTNAME_MAX_LENGTH);
    return h;
  }

  private static String stripTrailingDot(String raw) {
    if (raw == null) return null;
    String h = raw.trim();
    return h.endsWith(".") ? h.substring(0, h.length() - 1) : h;
  }

  /**
   * NetBIOS names are space-padded and carry a "&lt;XX&gt;" suffix type byte. Only the machine-name
   * suffixes (00 = Workstation, 20 = Server service) identify the host itself; group/browser
   * suffixes (1b/1c/1d/1e = domain-master/browser, etc.) name the workgroup, not the host, so they
   * are dropped to avoid labelling every member with the workgroup name.
   */
  private String cleanNetbiosName(String raw) {
    if (raw == null) return null;
    String h = firstValue(raw);
    if (h == null) return null;
    int lt = h.indexOf('<');
    String suffix = null;
    if (lt >= 0) {
      int gt = h.indexOf('>', lt);
      suffix = (gt > lt ? h.substring(lt + 1, gt) : h.substring(lt + 1)).trim().toLowerCase();
      h = h.substring(0, lt);
    }
    if (suffix != null && !suffix.equals("00") && !suffix.equals("20")) return null;
    h = h.trim();
    return h.isEmpty() ? null : h;
  }

  /** Rejects mDNS service-discovery names ("_http._tcp.local") and keeps real host names. */
  private boolean isPlausibleHostName(String name) {
    if (name == null || name.isBlank()) return false;
    String lower = name.toLowerCase();
    return !lower.startsWith("_") && !lower.contains("._tcp") && !lower.contains("._udp")
        && !lower.contains("._sub");
  }

  /**
   * The address a reverse-DNS question names: {@code 4.3.2.1.in-addr.arpa} is {@code 1.2.3.4}, and
   * an {@code ip6.arpa} name (32 nibbles, last first) is the IPv6 address in RFC 5952 form, as
   * tshark writes it elsewhere, so the claim lands on the same host. Null for anything else.
   */
  static String arpaToIp(String qryName) {
    if (qryName == null) return null;
    // DNS query names may carry a trailing dot ("4.3.2.1.in-addr.arpa."); strip it first.
    String name = stripTrailingDot(qryName).toLowerCase();
    if (name.endsWith(".ip6.arpa")) return ip6ArpaToIp(name.substring(0, name.length() - ".ip6.arpa".length()));
    if (!name.endsWith(".in-addr.arpa")) return null;
    String labels = name.substring(0, name.length() - ".in-addr.arpa".length());
    String[] octets = labels.split("\\.");
    if (octets.length != 4) return null;
    StringBuilder sb = new StringBuilder();
    for (int i = octets.length - 1; i >= 0; i--) {
      sb.append(octets[i]);
      if (i > 0) sb.append('.');
    }
    // Written as tshark writes it ("010" is 10), so the claim lands on the same host.
    byte[] bytes = com.tracepcap.common.net.Cidr.addressBytes(sb.toString());
    return bytes != null && bytes.length == 4 ? com.tracepcap.common.net.Cidr.formatAddress(bytes) : null;
  }

  private static String ip6ArpaToIp(String labels) {
    String[] nibbles = labels.split("\\.");
    if (nibbles.length != 32) return null; // a partial name is a zone, not one host
    byte[] b = new byte[16];
    for (int i = 0; i < 32; i++) {
      String n = nibbles[31 - i];
      if (n.length() != 1 || Character.digit(n.charAt(0), 16) < 0) return null;
      int v = Character.digit(n.charAt(0), 16);
      b[i / 2] |= (byte) (i % 2 == 0 ? v << 4 : v);
    }
    return com.tracepcap.common.net.Cidr.formatAddress(b);
  }

}
