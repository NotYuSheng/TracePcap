package com.tracepcap.knowledge.contributor;

import com.tracepcap.common.text.Humanize;
import com.tracepcap.analysis.spi.KerberosLookup;
import com.tracepcap.analysis.spi.KerberosLookup.KerberosFacts;
import com.tracepcap.knowledge.spi.CaseKnowledgeBuilder;
import com.tracepcap.knowledge.spi.EntityRef;
import com.tracepcap.knowledge.spi.Finding;
import com.tracepcap.knowledge.spi.Grade;
import com.tracepcap.knowledge.spi.KnowledgeContext;
import com.tracepcap.knowledge.spi.KnowledgeContributor;
import com.tracepcap.knowledge.spi.Severity;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Component;

/**
 * Attacks on accounts and tickets, from the replies a domain controller sent (#1267):
 *
 * <ul>
 *   <li><b>Password guessing</b>: one host failing to sign in as many different accounts (wrong
 *       password, {@code KDC_ERR_PREAUTH_FAILED}, or no such account, {@code
 *       KDC_ERR_C_PRINCIPAL_UNKNOWN}) within ten minutes: password spraying, or user enumeration
 *       when the names mostly don't exist. {@code KDC_ERR_PREAUTH_REQUIRED} is how every Windows
 *       sign-in starts and never counts. Many wrong passwords for <em>one</em> account isn't
 *       posted: a service left with an old password retries all day and looks the same.
 *   <li><b>A weak ticket</b>: a ticket encrypted with RC4 or DES from a domain controller that
 *       issues AES tickets elsewhere in the capture. A domain that only does RC4 is old, not
 *       attacked; one that does both was asked for the weak one. Service tickets that way are how
 *       Kerberoasting gets crackable tickets; a sign-in ticket that way is what Skeleton Key does.
 * </ul>
 *
 * <p>Measured on nine Windows-domain captures (the eval exercises and holdouts): no wrong
 * passwords, no unknown accounts and only AES tickets, so neither fires; PCAP-ATTACK's kerbrute
 * capture fails 9 accounts from one host, and its Skeleton Key capture has one RC4 sign-in ticket
 * among AES ones. AS-REP roasting (an account without pre-authentication) isn't detectable: Suricata
 * doesn't log whether a request carried pre-authentication.
 */
@Component
public class KerberosContributor implements KnowledgeContributor {

  public static final String KERBEROS_ATTACK = "kerberos-attack";
  public static final String PASSWORD_GUESSING = "password-guessing";
  public static final String WEAK_TICKET = "weak-ticket";

  static final String WRONG_PASSWORD = "KDC_ERR_PREAUTH_FAILED";
  static final String NO_SUCH_ACCOUNT = "KDC_ERR_C_PRINCIPAL_UNKNOWN";

  /** Distinct accounts one host failed as, from five up: kerbrute's 9, a clean domain's 0. */
  static final int MIN_ACCOUNTS = 5;

  /** Failures this close together are one burst. Kerbrute's nine took seconds. */
  static final java.time.Duration WINDOW = java.time.Duration.ofMinutes(10);

  /** The password-guessing rule in words, for a near miss (#1294) and an answer's steps alike. */
  public static final String GUESSING_RULE =
      "Failing to sign in as five or more accounts within ten minutes is password guessing: mostly"
          + " unknown names is user enumeration, mostly wrong passwords is spraying. \"Pre-authentication"
          + " required\" starts every Windows sign-in and never counts.";

  private final ObjectProvider<KerberosLookup> kerberos;

  public KerberosContributor(ObjectProvider<KerberosLookup> kerberos) {
    this.kerberos = kerberos;
  }

  @Override
  public String name() {
    return "kerberos";
  }

  @Override
  public void contribute(KnowledgeContext context, CaseKnowledgeBuilder board) {
    KerberosLookup lookup = kerberos.getIfAvailable();
    if (lookup == null) return;
    List<KerberosFacts> replies = lookup.forFile(context.fileId());
    if (!replies.isEmpty()) post(replies, board);
  }

  /** The board-facing part, unit-testable without a lookup. */
  static void post(List<KerberosFacts> replies, CaseKnowledgeBuilder board) {
    guessing(replies, board);
    weakTickets(replies, board);
  }

  private static void guessing(List<KerberosFacts> replies, CaseKnowledgeBuilder board) {
    Map<List<String>, List<KerberosFacts>> byPair = new LinkedHashMap<>();
    for (KerberosFacts r : replies) {
      if (r.client() == null || r.kdc() == null || r.errorCode() == null) continue;
      if (!WRONG_PASSWORD.equals(r.errorCode()) && !NO_SUCH_ACCOUNT.equals(r.errorCode())) continue;
      byPair.computeIfAbsent(List.of(r.client(), r.kdc()), k -> new ArrayList<>()).add(r);
    }
    byPair.forEach((pair, all0) -> {
      // The busiest burst, not the whole capture: a terminal server or NAT gateway sees ordinary
      // typos from many users over a day; a guessing tool fails them within seconds.
      List<KerberosFacts> errors = busiestWindow(all0);
      Set<String> wrong = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
      Set<String> unknown = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
      for (KerberosFacts r : errors) {
        if (r.account() == null) continue;
        if (WRONG_PASSWORD.equals(r.errorCode())) wrong.add(r.account());
        else unknown.add(r.account());
      }
      Set<String> all = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
      all.addAll(wrong);
      all.addAll(unknown);
      if (all.size() < MIN_ACCOUNTS) {
        // Two to four: tested and short of the rule, worth saying so (#1294). One is a typo.
        if (all.size() >= 2) {
          board.addFinding(new com.tracepcap.knowledge.spi.Considered("kerberos-attack",
                  pair.get(0) + " → " + pair.get(1), GUESSING_RULE,
                  "failed to sign in as " + all.size() + " accounts (" + list(all) + ") within ten minutes;"
                      + " " + MIN_ACCOUNTS + " are needed to call it password guessing.",
                  conversations(errors))
              .toFinding("suricata", List.of(EntityRef.host(pair.get(0)), EntityRef.host(pair.get(1)))));
        }
        return;
      }

      List<String> lines = new ArrayList<>();
      if (!wrong.isEmpty()) lines.add("Wrong password for " + Humanize.plural(wrong.size(), "account") + ": " + list(wrong));
      if (!unknown.isEmpty()) lines.add("No such account for " + Humanize.plural(unknown.size(), "name") + ": " + list(unknown));
      Map<String, Object> attrs = new LinkedHashMap<>();
      attrs.put("technique", PASSWORD_GUESSING);
      attrs.put("client", pair.get(0));
      attrs.put("kdc", pair.get(1));
      attrs.put("wrongPassword", new ArrayList<>(wrong));
      attrs.put("noSuchAccount", new ArrayList<>(unknown));
      attrs.put("accounts", all.size());
      attrs.put("operations", lines);
      first(errors, attrs);
      board.addFinding(new Finding(
          KERBEROS_ATTACK,
          pair.get(0) + " failed to sign in as " + Humanize.plural(all.size(), "account") + " at " + pair.get(1),
          Severity.HIGH, Grade.MEASURED, "suricata",
          List.of(EntityRef.host(pair.get(0)), EntityRef.host(pair.get(1))),
          conversations(errors), attrs));
    });
  }

  private static void weakTickets(List<KerberosFacts> replies, CaseKnowledgeBuilder board) {
    // KDCs that issued a ticket with strong encryption somewhere in the capture.
    Set<String> strong = new HashSet<>();
    for (KerberosFacts r : replies) {
      if (isTicket(r) && !r.weak() && r.encryption() != null) strong.add(r.kdc());
    }
    Map<List<String>, List<KerberosFacts>> byPair = new LinkedHashMap<>();
    for (KerberosFacts r : replies) {
      if (!isTicket(r) || !r.weak() || r.client() == null || !strong.contains(r.kdc())) continue;
      byPair.computeIfAbsent(List.of(r.client(), r.kdc()), k -> new ArrayList<>()).add(r);
    }
    byPair.forEach((pair, weak) -> {
      Set<String> services = new TreeSet<>(), signIns = new TreeSet<>(), lines = new java.util.LinkedHashSet<>();
      for (KerberosFacts r : weak) {
        boolean signIn = r.msgType().contains("AS_REP");
        String who = r.account() != null ? r.account() : "an account";
        if (signIn) signIns.add(who);
        else if (r.service() != null) services.add(r.service());
        String enc = r.encryption() != null ? r.encryption() : "weak encryption";
        String svc = r.service() != null ? r.service() : "an unnamed service";
        lines.add((signIn ? "Sign-in ticket for " + who : "Service ticket for " + svc + " (" + who + ")")
            + ", " + enc + (r.count() > 1 ? " (" + r.count() + "×)" : ""));
      }
      Map<String, Object> attrs = new LinkedHashMap<>();
      attrs.put("technique", WEAK_TICKET);
      attrs.put("client", pair.get(0));
      attrs.put("kdc", pair.get(1));
      attrs.put("services", new ArrayList<>(services));
      attrs.put("signIns", new ArrayList<>(signIns));
      attrs.put("operations", new ArrayList<>(lines));
      first(weak, attrs);
      int tickets = weak.stream().mapToInt(KerberosFacts::count).sum();
      attrs.put("tickets", tickets);
      board.addFinding(new Finding(
          KERBEROS_ATTACK,
          pair.get(1) + " issued " + Humanize.plural(tickets, "weak ticket") + " to " + pair.get(0)
              + " while using AES elsewhere",
          Severity.MEDIUM, Grade.MEASURED, "suricata",
          List.of(EntityRef.host(pair.get(0)), EntityRef.host(pair.get(1))),
          conversations(weak), attrs));
    });
  }

  /** The failures in the ten-minute stretch with the most distinct accounts. */
  static List<KerberosFacts> busiestWindow(List<KerberosFacts> errors) {
    if (errors.stream().anyMatch(r -> r.firstTime() == null)) return errors; // can't tell: all
    List<KerberosFacts> sorted = new ArrayList<>(errors);
    sorted.sort(java.util.Comparator.comparing(KerberosFacts::firstTime));
    List<KerberosFacts> best = List.of();
    int bestAccounts = -1;
    for (int i = 0; i < sorted.size(); i++) {
      LocalDateTime end = sorted.get(i).firstTime().plus(WINDOW);
      List<KerberosFacts> w = new ArrayList<>();
      Set<String> accounts = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
      for (int j = i; j < sorted.size() && !sorted.get(j).firstTime().isAfter(end); j++) {
        w.add(sorted.get(j));
        if (sorted.get(j).account() != null) accounts.add(sorted.get(j).account());
      }
      if (accounts.size() > bestAccounts) {
        bestAccounts = accounts.size();
        best = w;
      }
    }
    return best;
  }

  private static boolean isTicket(KerberosFacts r) {
    return r.msgType() != null && r.msgType().endsWith("_REP") && r.kdc() != null;
  }

  private static void first(List<KerberosFacts> rs, Map<String, Object> attrs) {
    LocalDateTime first = null;
    for (KerberosFacts r : rs) {
      if (r.firstTime() != null && (first == null || r.firstTime().isBefore(first))) first = r.firstTime();
    }
    if (first != null) attrs.put("firstSeen", TrafficContributor.utc(first));
  }

  private static List<String> conversations(List<KerberosFacts> rs) {
    Set<UUID> ids = new java.util.LinkedHashSet<>();
    for (KerberosFacts r : rs) if (r.conversationId() != null) ids.add(r.conversationId());
    return ids.stream().map(UUID::toString).toList();
  }

  /** "admin, bob, svc-01 and 4 more". */
  static String list(Set<String> names) {
    List<String> l = new ArrayList<>(names);
    if (l.size() <= 6) return String.join(", ", l);
    return String.join(", ", l.subList(0, 5)) + " and " + (l.size() - 5) + " more";
  }
}
