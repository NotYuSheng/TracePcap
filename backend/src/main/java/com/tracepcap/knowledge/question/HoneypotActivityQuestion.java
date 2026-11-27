package com.tracepcap.knowledge.question;

import com.tracepcap.knowledge.contributor.HoneypotContributor;
import com.tracepcap.knowledge.spi.Answer;
import com.tracepcap.knowledge.spi.CaseKnowledge;
import com.tracepcap.knowledge.spi.Category;
import com.tracepcap.knowledge.spi.EntityRef;
import com.tracepcap.knowledge.spi.Finding;
import com.tracepcap.knowledge.spi.Grade;
import com.tracepcap.knowledge.spi.Relationship;
import com.tracepcap.knowledge.spi.StandardQuestion;
import com.tracepcap.knowledge.spi.Step;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.stereotype.Component;

/**
 * "What reached the honeypots?" (docs/architecture/investigation-framework.rst, "How a honeypot
 * changes other answers"). A decoy has no real users, so the hosts that connect to it are the
 * subjects worth reporting: scanners, brute-forcers, exploit attempts. And a decoy that talks to a
 * malware C2 is recording the attack, not infected by it, so it is answered here rather than as a
 * victim ({@link VictimQuestion} leaves honeypots out).
 */
@Component
public class HoneypotActivityQuestion implements StandardQuestion {

  static final String QUESTION = "honeypot-activity";

  /** Groups of hosts listed, the busiest first; the rest as one line. */
  static final int MAX_GROUPS = 10;

  /** Hosts named in one group's headline; the rest are counted (all are its subjects). */
  static final int MAX_NAMED = 5;

  @Override
  public String question() {
    return QUESTION;
  }

  @Override
  public Set<Category> categories() {
    return Set.of(Category.SCANNER);
  }

  @Override
  public List<Answer> answer(CaseKnowledge board) {
    Map<String, String> honeypots = HoneypotContributor.honeypots(board);
    if (honeypots.isEmpty()) return List.of();
    List<Answer> answers = new ArrayList<>(decoysThatReachedAC2(board, honeypots));

    // Hosts that reached the same decoys are one answer: a scan from six containers reads as one
    // finding, not six near-identical lines.
    Map<Map<String, String>, List<Finding>> groups = new LinkedHashMap<>();
    for (Finding f : board.findingsOfCategory(HoneypotContributor.CONTACT)) {
      groups.computeIfAbsent(reached(f), k -> new ArrayList<>()).add(f);
    }
    groups.values().forEach(g -> g.sort(Comparator.comparingLong(HoneypotActivityQuestion::conversations)
        .reversed().thenComparing(f -> host(f))));
    List<List<Finding>> ordered = new ArrayList<>(groups.values());
    ordered.sort(Comparator.comparingLong((List<Finding> g) -> g.stream()
        .mapToLong(HoneypotActivityQuestion::conversations).sum()).reversed()
        .thenComparing(g -> host(g.get(0))));
    ordered.stream().limit(MAX_GROUPS).forEach(g -> answers.add(reached(g)));
    if (ordered.size() > MAX_GROUPS) {
      int more = ordered.subList(MAX_GROUPS, ordered.size()).stream().mapToInt(List::size).sum();
      answers.add(new Answer(QUESTION,
          more + " more host" + (more == 1 ? "" : "s") + " reached a honeypot, with fewer conversations",
          Grade.INFERRED, List.of(), List.of(more + " more hosts"), Map.of("more", more)));
    }
    return answers;
  }

  /**
   * "198.51.100.101 reached the Cowrie honeypot 198.51.100.22 (6 conversations): …", or for several
   * hosts that reached the same decoys, "7 hosts (198.51.100.101, …) reached …".
   */
  private static Answer reached(List<Finding> group) {
    Map<String, String> reached = reached(group.get(0));
    long n = group.stream().mapToLong(HoneypotActivityQuestion::conversations).sum();
    List<String> hosts = group.stream().map(HoneypotActivityQuestion::host).toList();
    List<String> targets = reached.entrySet().stream()
        .map(e -> "the " + e.getValue() + " " + e.getKey()).toList();
    String who;
    if (hosts.size() == 1) {
      who = hosts.get(0);
    } else {
      List<String> named = new ArrayList<>(hosts.subList(0, Math.min(MAX_NAMED, hosts.size())));
      if (hosts.size() > MAX_NAMED) named.add(hosts.size() - MAX_NAMED + " more");
      who = hosts.size() + " hosts (" + join(named) + ")";
    }
    String headline = who + " reached " + join(targets) + " (" + n + " conversation"
        + (n == 1 ? "" : "s") + "): a decoy has no real users, so this is scanning or an attack";
    Map<String, Object> attrs = new LinkedHashMap<>();
    attrs.put("hosts", hosts);
    attrs.put("honeypots", reached);
    attrs.put("conversations", n);
    List<Step> steps = new ArrayList<>();
    reached.forEach((ip, name) -> steps.add(Step.of(
        ip + " is a " + name + " (the Honeypot answer shows how).", null, Grade.INFERRED)));
    for (Finding f : group) {
      steps.add(new Step(f.summary() + ".", Derivations.RULE_DECOY_CONTACT, Grade.MEASURED, f.evidence()));
    }
    return new Answer(QUESTION, headline, Grade.INFERRED,
        hosts.stream().map(EntityRef::host).toList(), group.stream().map(Finding::summary).toList(),
        attrs).withDerivation(steps);
  }

  @SuppressWarnings("unchecked")
  private static Map<String, String> reached(Finding f) {
    return new java.util.TreeMap<>((Map<String, String>) f.attributes().get("honeypots"));
  }

  private static String host(Finding f) {
    return String.valueOf(f.attributes().get("host"));
  }

  /**
   * A honeypot that talked to a known C2: the attack it was put there to record. The C2 itself is
   * still answered as one; only the decoy isn't a victim.
   */
  private static List<Answer> decoysThatReachedAC2(CaseKnowledge board, Map<String, String> honeypots) {
    Set<EntityRef> c2s = new LinkedHashSet<>();
    board.relationshipsWithPredicate("c2-of").forEach(r -> c2s.add(r.from()));
    if (c2s.isEmpty()) return List.of();
    // decoy → the C2s it talked to, as the board names them (one per server, however many edges)
    Map<EntityRef, Set<EntityRef>> byDecoy = new LinkedHashMap<>();
    for (Relationship comm : board.relationshipsWithPredicate("communicates-with")) {
      if (honeypots.containsKey(comm.from().key()) && c2s.contains(comm.to())) {
        byDecoy.computeIfAbsent(comm.from(), k -> new LinkedHashSet<>()).add(comm.to());
      }
    }
    List<Answer> out = new ArrayList<>();
    byDecoy.forEach((ref, servers) -> {
      String decoy = ref.key();
      String name = honeypots.get(decoy);
      List<String> c2 = servers.stream().map(EntityRef::key).toList();
      Map<String, Object> attrs = new LinkedHashMap<>();
      attrs.put("host", decoy);
      attrs.put("decoy", name);
      attrs.put("c2", c2);
      List<Step> steps = new ArrayList<>();
      steps.add(Step.of(decoy + " is a " + name + " (the Honeypot answer shows how).", null, Grade.INFERRED));
      for (EntityRef server : servers) {
        steps.add(new Step(decoy + " talked to " + server.key() + ", a known command-and-control server.",
            Derivations.RULE_DECOY_C2, Grade.INFERRED, Derivations.conversationsBetween(board, ref, server)));
      }
      out.add(new Answer(QUESTION,
          decoy + ", a " + name + ", contacted the known C2 " + join(c2)
              + ": the attack it was set up to record, not an infection",
          Grade.INFERRED, List.of(ref),
          c2.stream().map(s -> "contacted C2 " + s).toList(), attrs).withDerivation(steps));
    });
    return out;
  }

  private static long conversations(Finding f) {
    return f.attributes().get("conversations") instanceof Number n ? n.longValue() : 0L;
  }

  private static String join(List<String> parts) {
    if (parts.size() <= 1) return String.join("", parts);
    return String.join(", ", parts.subList(0, parts.size() - 1)) + " and " + parts.get(parts.size() - 1);
  }
}
