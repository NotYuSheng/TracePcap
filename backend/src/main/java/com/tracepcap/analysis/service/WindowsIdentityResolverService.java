package com.tracepcap.analysis.service;

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
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Resolves the Windows identity (real name / logon username) of hosts in a PCAP capture, from two
 * signals (#809, motivated by the #808 CTF-demo gap — TracePcap had zero LDAP/Kerberos parsing and
 * missed a victim's real identity that a manual Wireshark filter found trivially):
 *
 * <ul>
 *   <li><b>Kerberos AS-REQ</b> ({@code kerberos.msg_type==10}) — the client's own authentication
 *       request names the principal requesting a ticket. Sent by the client itself, so this is
 *       MEASURED-grade: unambiguous proof of who is logged in at that IP. AS-REP/TGS-REP are
 *       deliberately not read: their source IP is the KDC, not the client, so including them would
 *       attribute the domain controller's own IP to every account it has ever issued a ticket for.
 *   <li><b>LDAP searchRequest DN</b> ({@code ldap.baseObject}) — a client's directory lookup names
 *       the account it is asking about, e.g. {@code "CN=Clark Collier,CN=Users,DC=example,DC=com"}.
 *       This is REPORTED-grade and weaker: it is a self-lookup pattern (a shell/Explorer resolving
 *       the current user's display name) in the common case, but nothing in the wire protocol
 *       guarantees the query is about the querying host's own identity rather than someone else's
 *       (an admin/helpdesk tool, for instance) — so it corroborates a Kerberos claim rather than
 *       standing alone with equal weight. That priority is applied by {@code WindowsDomainAuthSignal}
 *       (the device-classification signal that consumes these claims); this class only records what
 *       it saw, conflict-preserving.
 * </ul>
 *
 * <p><b>Filtering by LDAP attribute name is deliberately not done.</b> An earlier design considered
 * restricting to {@code searchRequest}s whose {@code AttributeDescription} includes an identity
 * attribute ({@code givenName}, {@code sn}, {@code displayName}, {@code sAMAccountName}, {@code
 * cn}, ...), but verified against a real capture this produces false positives: a request for
 * {@code CN=Certificate Templates,CN=Public Key Services,...,DC=example,DC=com} legitimately
 * requests {@code displayName} and {@code cn} too — those are attributes of a certificate template,
 * not a person. The robust discriminator is the DN's own shape: Active Directory person objects
 * live under {@code CN=Users}; infrastructure objects do not. {@link #PERSON_DN} matches on that.
 *
 * <p><b>Never parses or persists a bind credential.</b> LDAP simple-bind-over-389 can carry a
 * cleartext password in {@code ldap.authentication.simple}. This class's tshark pass does not
 * request that field, and never will — deliberately, not by oversight. Do not add it.
 *
 * <p>Machine-account principals (Kerberos {@code CNameString} ending in {@code $}, e.g. {@code
 * DESKTOP-ABC123$}) are excluded: they identify the computer, not a person. The trailing '$' has no
 * case, so this exclusion is inherently case-insensitive regardless of how the rest of the
 * principal is cased (both {@code desktop-abc123$} and {@code DESKTOP-ABC123$} appear in the wild).
 *
 * <p>Runs as a single read-only tshark pass and never throws — on any failure it returns whatever
 * was collected so far (possibly empty), matching {@link HostnameResolverService}'s contract.
 */
@Slf4j
@Service
public class WindowsIdentityResolverService {

  private static final int USERNAME_MAX_LENGTH = 255;

  /** A Kerberos AS-REQ named this principal — the client authenticated as it. MEASURED-grade. */
  public static final String SOURCE_KERBEROS_AS_REQ = "kerberos_as_req";

  /** An LDAP directory lookup queried this account's DN. REPORTED-grade (weaker, see class doc). */
  public static final String SOURCE_LDAP_DN = "ldap_dn";

  /** AS-REQ, per the RFC 4120 message-type registry — the only Kerberos message this class reads. */
  private static final String KERBEROS_MSG_TYPE_AS_REQ = "10";

  /**
   * Active Directory person objects live under CN=Users; infrastructure objects do not (see class
   * doc). The capture group uses {@code (?:[^,\\]|\\.)+} rather than {@code [^,]+} so an RFC 4514
   * backslash-escaped comma inside the CN value (e.g. {@code CN=Collier\, Clark,CN=Users,DC=...})
   * doesn't prematurely end the match.
   */
  private static final Pattern PERSON_DN =
      Pattern.compile("^CN=((?:[^,\\\\]|\\\\.)+),CN=Users,DC=.*$", Pattern.CASE_INSENSITIVE);

  /** One claim: {@code source} asserted that {@code ip}'s logged-in/queried identity is {@code username}. */
  public record Claim(String ip, String username, String source) {}

  /** Scans the capture and returns every Windows-identity claim found via Kerberos AS-REQ or LDAP. */
  public List<Claim> resolve(File pcapFile) {
    // Concurrent: the stdout reader (background thread) writes while the main thread reads size().
    Map<Claim, Boolean> result = new ConcurrentHashMap<>();

    // Fields (pipe-separated, first occurrence only):
    //   0 frame.number  1 ip.src  2 ip.dst
    //   3 ldap.baseObject
    //   4 kerberos.msg_type  5 kerberos.CNameString
    // The filter keys on ldap.baseObject alone — it is a searchRequest field, so it already selects
    // the right message type. It deliberately does NOT also require ldap.AttributeDescription: a
    // searchRequest asking for all attributes carries an empty attribute list and no
    // AttributeDescription, and requiring it would silently drop those person lookups — the exact
    // recall gap #808/#809 exists to close. The DN-shape regex (see class doc) is what filters
    // person objects from infrastructure, not the presence of an attribute list.
    ProcessBuilder pb =
        new ProcessBuilder(
            "tshark",
            "-r",
            pcapFile.getAbsolutePath(),
            "-Y",
            "ldap.baseObject || (kerberos.msg_type==10 and kerberos.CNameString)",
            "-T",
            "fields",
            "-E",
            "separator=|",
            "-E",
            "occurrence=f",
            "-e",
            "frame.number",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "ldap.baseObject",
            "-e",
            "kerberos.msg_type",
            "-e",
            "kerberos.CNameString");
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
                    if (!line.isEmpty()) parseRow(line.split("\\|", -1), result);
                  }
                } catch (Exception ignored) {
                  // best-effort
                }
              });

      boolean finished = process.waitFor(2, TimeUnit.MINUTES);
      if (!finished) {
        log.warn("Windows identity resolution timed out; returning {} partial result(s)", result.size());
      } else {
        int exit = process.exitValue();
        if (exit != 0) {
          log.warn("Windows identity resolution: tshark exited with code {}; results may be partial", exit);
        }
        try {
          stdoutTask.get(5, TimeUnit.SECONDS);
        } catch (Exception ignored) {
          // best-effort
        }
      }
    } catch (InterruptedException e) {
      log.warn("Windows identity resolution interrupted");
      Thread.currentThread().interrupt();
    } catch (Exception e) {
      log.warn("Windows identity resolution failed: {}", e.getMessage());
    } finally {
      if (process != null) process.destroyForcibly();
      if (ioExecutor != null) ioExecutor.shutdownNow();
    }

    log.info("Collected {} Windows identity claim(s) from Kerberos/LDAP", result.size());
    return new ArrayList<>(result.keySet());
  }

  // ── Row parsing ─────────────────────────────────────────────────────────────

  private void parseRow(String[] f, Map<Claim, Boolean> result) {
    if (f.length < 6) return;

    String baseObject = trimToNull(f[3]);
    if (baseObject != null) {
      String personName = personNameFromDn(baseObject);
      if (personName != null) {
        record(result, firstValue(f[1]), personName, SOURCE_LDAP_DN);
      }
      return;
    }

    if (KERBEROS_MSG_TYPE_AS_REQ.equals(trimToNull(f[4]))) {
      String principal = trimToNull(f[5]);
      if (principal != null && !isMachineAccount(principal)) {
        record(result, firstValue(f[1]), principal, SOURCE_KERBEROS_AS_REQ);
      }
    }
  }

  /** Records one claim verbatim. No winner-picking here — that is the adjudicator's job. */
  private void record(Map<Claim, Boolean> result, String ip, String rawUsername, String source) {
    if (!isUsableIp(ip)) return;
    String username = cleanUsername(rawUsername);
    if (username == null) return;
    result.putIfAbsent(new Claim(ip, username, source), Boolean.TRUE);
  }

  // ── Field helpers ────────────────────────────────────────────────────────────

  /**
   * Extracts the person's name from an AD distinguished name's leading CN component, when the DN
   * shape indicates a person object ({@code CN=Users} container) — see class doc for why this is
   * the discriminator rather than which attributes were requested. The captured CN value is
   * RFC 4514-unescaped so a name like {@code CN=Collier\, Clark,...} is returned as the human-
   * readable {@code "Collier, Clark"}, not with its wire-format escape backslashes.
   */
  static String personNameFromDn(String baseObject) {
    Matcher m = PERSON_DN.matcher(baseObject.trim());
    return m.matches() ? unescapeRfc4514(m.group(1)).trim() : null;
  }

  /**
   * Undoes RFC 4514 attribute-value escaping: a backslash before a special character escapes it
   * literally ({@code \,} → {@code ,}), and a backslash before two hex digits is that byte
   * ({@code \20} → space). Names rarely use the hex form, but both are handled so the displayed
   * value is what a human would read, never the on-the-wire escape sequence.
   */
  static String unescapeRfc4514(String s) {
    if (s == null || s.indexOf('\\') < 0) return s;
    StringBuilder out = new StringBuilder(s.length());
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      if (c == '\\' && i + 1 < s.length()) {
        char n1 = s.charAt(i + 1);
        if (i + 2 < s.length() && isHex(n1) && isHex(s.charAt(i + 2))) {
          out.append((char) Integer.parseInt(s.substring(i + 1, i + 3), 16));
          i += 2;
        } else {
          out.append(n1);
          i += 1;
        }
      } else {
        out.append(c);
      }
    }
    return out.toString();
  }

  private static boolean isHex(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
  }

  /** Machine-account principals end in '$', which has no case, so this needs no case-folding. */
  static boolean isMachineAccount(String principal) {
    return principal.endsWith("$");
  }

  /** tshark may join multiple occurrences with ','; take the first non-blank token. */
  private String firstValue(String field) {
    if (field == null) return null;
    String trimmed = field.trim();
    if (trimmed.isEmpty()) return null;
    int comma = trimmed.indexOf(',');
    return comma >= 0 ? trimmed.substring(0, comma).trim() : trimmed;
  }

  private String cleanUsername(String raw) {
    if (raw == null) return null;
    String u = raw.trim();
    if (u.isEmpty()) return null;
    if (u.length() > USERNAME_MAX_LENGTH) u = u.substring(0, USERNAME_MAX_LENGTH);
    return u;
  }

  private String trimToNull(String raw) {
    if (raw == null) return null;
    String t = raw.trim();
    return t.isEmpty() ? null : t;
  }

  private boolean isUsableIp(String ip) {
    return ip != null && !ip.isBlank() && !ip.equals("0.0.0.0") && !ip.equals("::");
  }
}
