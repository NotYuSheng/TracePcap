package com.tracepcap.knowledge.question;

import com.tracepcap.knowledge.spi.CaseKnowledge;
import com.tracepcap.knowledge.spi.EntityRef;
import com.tracepcap.knowledge.spi.Finding;
import com.tracepcap.knowledge.spi.Grade;
import com.tracepcap.knowledge.spi.Relationship;
import com.tracepcap.knowledge.spi.Step;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * How the standard questions reached their answers, step by step (#1293). The rules are written
 * here once, in words, so the same rule reads the same in every answer and matches what the code
 * does.
 */
final class Derivations {

  private Derivations() {}

  static final String RULE_NAMED_C2 =
      "A Suricata malware rule that names a server makes it that malware family's command-and-control"
          + " server.";
  static final String RULE_UNNAMED_C2 =
      "A rule about command-and-control traffic that names no family still marks its server as a"
          + " C2, for unidentified malware.";
  static final String RULE_FINGERPRINT =
      "A stream that opens with a malware family's own check-in is that family's C2, even when no"
          + " rule fired.";
  static final String RULE_SUSPECTED =
      "Reputation alone never makes a C2. A listed server becomes a suspected C2 only when a host"
          + " already talking to a confirmed C2 reaches it by bare IP, in repeated rounds (or seconds"
          + " after another such server).";
  static final String RULE_INSTALL_CHAIN =
      "A RAT checking in to a bare IP minutes after a script engine on the same host fetched a large"
          + " payload from another server is how it was planted: its server is treated as a C2.";
  static final String RULE_VICTIM =
      "A host inside the network that talks to a known C2 is treated as infected: the victim.";
  static final String RULE_FAMILY =
      "A detector that names a malware family identifies it: a Suricata rule by name, or the stream"
          + " classifier by the family's own check-in.";
  static final String RULE_KERBEROS_SIGN_IN =
      "A host that asks the domain controller for a ticket as an account is signed in as that account.";
  static final String RULE_NTLM_SIGN_IN =
      "A host that completes an NTLM sign-in as an account is signed in as that account.";
  static final String RULE_LDAP_SIGN_IN =
      "A host that looks its own user up in the directory names who uses it: a claim on the wire,"
          + " not a sign-in.";
  static final String RULE_SAMR_SIGN_IN =
      "A host that asks the domain controller about an account (SAMR) names who uses it: a claim on"
          + " the wire, not a sign-in.";
  static final String RULE_REMOTE_ACCESS =
      "A remote-admin tool talking to a server outside the network is reported for confirmation:"
          + " IT uses these tools too, so it is never called a C2 on this alone.";
  static final String RULE_TRANSFER =
      "A transfer of 5 MB or more to a server outside the network that isn't a known CDN or cloud"
          + " provider is reported for review, never asserted as exfiltration.";
  static final String RULE_DOWNLOAD =
      "An executable, script, archive or installer a host fetched from outside over a real HTTP"
          + " transfer is listed with its SHA-256.";

  /** What each lateral-movement technique means (#1266), as a step's rule. */
  static String lateralRule(String technique) {
    return switch (technique) {
      case "remote-service" -> "Creating or repointing a service on another machine over RPC (svcctl)"
          + " makes it run a command: how PsExec and smbexec work.";
      case "scheduled-task" -> "Registering a scheduled task on another machine runs a command there.";
      case "wmi-exec" -> "Calling WMI's ExecMethod on another machine is how a process is started there.";
      case "admin-share-copy" -> "Copying a program to an admin share (ADMIN$, C$) is how remote tools"
          + " stage what they run.";
      case "dcsync" -> "Asking a domain controller to replicate directory data (DRSGetNCChanges) from a"
          + " host not seen acting as a domain controller is what DCSync looks like.";
      default -> null;
    };
  }

  /** What each Kerberos finding means (#1267), as a step's rule. */
  static String kerberosRule(String technique) {
    return "weak-ticket".equals(technique)
        ? "A domain controller that issues AES tickets but gave this host an RC4 or DES one was asked"
            + " for the weak one: what Kerberoasting and Skeleton Key do. An RC4-only domain doesn't count."
        : "Failing to sign in as five or more accounts within ten minutes is password guessing: mostly"
            + " unknown names is user enumeration, mostly wrong passwords is spraying. \"Pre-authentication"
            + " required\" starts every Windows sign-in and never counts.";
  }

  private static final Pattern C2_RULE = Pattern.compile("(?i)\\b(CnC|C2|Command and Control)\\b");

  /**
   * The steps that made {@code c2} a C2: each alert naming it (grouped by rule), the stream
   * classifier's match, a corroboration chain; then where it is and when it was first reached.
   */
  static List<Step> c2(CaseKnowledge board, EntityRef c2, Set<String> families) {
    List<Step> steps = new ArrayList<>();
    for (Relationship r : board.relationshipsWithPredicate("c2-of")) {
      if (!r.from().equals(c2) || r.attributes().get("corroboration") == null) continue;
      String kind = String.valueOf(r.attributes().get("corroboration"));
      steps.add(Step.of(String.valueOf(r.attributes().getOrDefault("reason", "")),
          "install-chain".equals(kind) ? RULE_INSTALL_CHAIN : RULE_SUSPECTED, Grade.INFERRED));
    }
    steps.addAll(alertSteps(board, c2, families));
    for (Finding f : board.findingsOfCategory("c2-classification")) {
      if (!f.concerns().contains(c2) || !"stream-fingerprint".equals(f.attributes().get("method"))) continue;
      steps.add(new Step(f.summary(), RULE_FINGERPRINT, Grade.INFERRED, f.evidence()));
    }
    Map<String, Object> e = board.entity(c2).map(x -> x.attributes()).orElse(Map.of());
    Object country = e.get("country"), org = e.get("org");
    if (country != null || org != null) {
      steps.add(Step.of(c2.key() + (org != null ? " is hosted by " + org + (country != null ? " in " + country : "")
          : " is in " + country) + ", from the offline GeoIP database.", null, Grade.INFERRED));
    }
    if (e.get("firstSeen") != null) {
      steps.add(Step.of("First contacted at "
          + com.tracepcap.knowledge.contributor.TrafficContributor.readable(e.get("firstSeen")) + ".",
          null, Grade.MEASURED));
    }
    return steps;
  }

  /** One step per rule that named this server (or its family), with every conversation it fired on. */
  static List<Step> alertSteps(CaseKnowledge board, EntityRef c2, Set<String> families) {
    Map<String, Set<String>> convsByRule = new LinkedHashMap<>();
    Map<String, Set<String>> pairsByRule = new LinkedHashMap<>();
    for (Finding f : board.findingsOfCategory("ids-alert")) {
      if (!f.concerns().contains(c2)) continue;
      String s = f.summary();
      boolean names = families.stream().anyMatch(fam -> !EntityRef.UNIDENTIFIED_MALWARE.equals(fam)
          && s.toUpperCase(Locale.ROOT).contains(fam.toUpperCase(Locale.ROOT)));
      boolean unnamed = families.contains(EntityRef.UNIDENTIFIED_MALWARE) && C2_RULE.matcher(s).find();
      if (!names && !unnamed) continue;
      convsByRule.computeIfAbsent(s, k -> new LinkedHashSet<>()).addAll(f.evidence());
      Object src = f.attributes().get("srcIp"), dst = f.attributes().get("dstIp");
      if (src != null && dst != null) pairsByRule.computeIfAbsent(s, k -> new LinkedHashSet<>()).add(src + " → " + dst);
    }
    List<Step> steps = new ArrayList<>();
    convsByRule.forEach((rule, convs) -> {
      boolean named = families.stream().anyMatch(fam -> !EntityRef.UNIDENTIFIED_MALWARE.equals(fam)
          && rule.toUpperCase(Locale.ROOT).contains(fam.toUpperCase(Locale.ROOT)));
      Set<String> pairs = pairsByRule.getOrDefault(rule, Set.of());
      steps.add(new Step(
          "Suricata rule \"" + rule + "\" fired"
              + (pairs.isEmpty() ? "" : " on " + String.join(", ", pairs))
              + (convs.size() > 1 ? ", in " + convs.size() + " conversations" : "") + ".",
          named ? RULE_NAMED_C2 : RULE_UNNAMED_C2, Grade.INFERRED, new ArrayList<>(convs)));
    });
    return steps;
  }

  /** The conversations between a host and a server, from the alerts that concern both. */
  static List<String> conversationsBetween(CaseKnowledge board, EntityRef host, EntityRef server) {
    Set<String> ids = new LinkedHashSet<>();
    for (String category : List.of("ids-alert", "c2-classification", "suspected-beacon")) {
      for (Finding f : board.findingsOfCategory(category)) {
        if (f.concerns().contains(host) && f.concerns().contains(server)) ids.addAll(f.evidence());
      }
    }
    return new ArrayList<>(ids);
  }

  /** How a sign-in was seen, in words. */
  static String signInSource(String source) {
    String s = source == null ? "" : source.toLowerCase(Locale.ROOT);
    if (s.contains("kerberos")) return "its own Kerberos AS-REQ";
    if (s.contains("ntlm")) return "an NTLM sign-in";
    if (s.contains("ldap")) return "an LDAP directory lookup";
    if (s.contains("samr")) return "a SAMR account lookup";
    return "an unknown source";
  }

  /** The rule for a sign-in, by where it was seen. */
  static String signInRule(String source) {
    String s = source == null ? "" : source.toLowerCase(Locale.ROOT);
    if (s.contains("kerberos")) return RULE_KERBEROS_SIGN_IN;
    if (s.contains("ntlm")) return RULE_NTLM_SIGN_IN;
    if (s.contains("ldap")) return RULE_LDAP_SIGN_IN;
    if (s.contains("samr")) return RULE_SAMR_SIGN_IN;
    return null;
  }
}
