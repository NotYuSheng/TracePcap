package com.tracepcap.knowledge.contributor;

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
 *       KDC_ERR_C_PRINCIPAL_UNKNOWN}): password spraying, or user enumeration when the names
 *       mostly don't exist. Or many wrong passwords for one account (brute force).
 *       {@code KDC_ERR_PREAUTH_REQUIRED} is how every Windows sign-in starts and never counts.
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

  /** Wrong passwords for one account, from ten up: a user mistyping does a few. */
  static final int MIN_WRONG_FOR_ONE = 10;

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
    byPair.forEach((pair, errors) -> {
      Set<String> wrong = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
      Set<String> unknown = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
      Map<String, Integer> wrongCount = new LinkedHashMap<>();
      for (KerberosFacts r : errors) {
        if (r.account() == null) continue;
        if (WRONG_PASSWORD.equals(r.errorCode())) {
          wrong.add(r.account());
          wrongCount.merge(r.account().toLowerCase(java.util.Locale.ROOT), r.count(), Integer::sum);
        } else {
          unknown.add(r.account());
        }
      }
      Set<String> all = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
      all.addAll(wrong);
      all.addAll(unknown);
      int mostForOne = wrongCount.values().stream().mapToInt(Integer::intValue).max().orElse(0);
      if (all.size() < MIN_ACCOUNTS && mostForOne < MIN_WRONG_FOR_ONE) return;

      List<String> lines = new ArrayList<>();
      if (!wrong.isEmpty()) lines.add("Wrong password for " + wrong.size() + " account" + plural(wrong.size()) + ": " + list(wrong));
      if (!unknown.isEmpty()) lines.add("No such account for " + unknown.size() + " name" + plural(unknown.size()) + ": " + list(unknown));
      Map<String, Object> attrs = new LinkedHashMap<>();
      attrs.put("technique", PASSWORD_GUESSING);
      attrs.put("client", pair.get(0));
      attrs.put("kdc", pair.get(1));
      attrs.put("wrongPassword", new ArrayList<>(wrong));
      attrs.put("noSuchAccount", new ArrayList<>(unknown));
      attrs.put("mostWrongForOneAccount", mostForOne);
      attrs.put("operations", lines);
      first(errors, attrs);
      board.addFinding(new Finding(
          KERBEROS_ATTACK,
          pair.get(0) + " failed to sign in as " + all.size() + " account" + plural(all.size()) + " at " + pair.get(1),
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
        lines.add((signIn ? "Sign-in ticket for " + who : "Service ticket for " + r.service() + " (" + who + ")")
            + ", " + r.encryption() + (r.count() > 1 ? " (" + r.count() + "×)" : ""));
      }
      Map<String, Object> attrs = new LinkedHashMap<>();
      attrs.put("technique", WEAK_TICKET);
      attrs.put("client", pair.get(0));
      attrs.put("kdc", pair.get(1));
      attrs.put("services", new ArrayList<>(services));
      attrs.put("signIns", new ArrayList<>(signIns));
      attrs.put("operations", new ArrayList<>(lines));
      first(weak, attrs);
      board.addFinding(new Finding(
          KERBEROS_ATTACK,
          pair.get(1) + " issued " + weak.size() + " weak ticket" + plural(weak.size()) + " to " + pair.get(0)
              + " while using AES elsewhere",
          Severity.MEDIUM, Grade.MEASURED, "suricata",
          List.of(EntityRef.host(pair.get(0)), EntityRef.host(pair.get(1))),
          conversations(weak), attrs));
    });
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

  private static String plural(int n) {
    return n == 1 ? "" : "s";
  }
}
