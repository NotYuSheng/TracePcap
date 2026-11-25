package com.tracepcap.knowledge.question;

import com.tracepcap.knowledge.contributor.IdsAlertRecordContributor;
import com.tracepcap.knowledge.spi.Answer;
import com.tracepcap.knowledge.spi.CaseKnowledge;
import com.tracepcap.knowledge.spi.EntityRef;
import com.tracepcap.knowledge.spi.EntityType;
import com.tracepcap.knowledge.spi.Finding;
import com.tracepcap.knowledge.spi.Grade;
import com.tracepcap.knowledge.spi.StandardQuestion;
import com.tracepcap.knowledge.spi.Category;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

/**
 * "Is a remote-access tool talking to the internet?" A remote-admin tool (NetSupport, AnyDesk,
 * ScreenConnect, TeamViewer…) seen checking in to a server outside the network. IT departments use
 * these tools, and so do attackers: NetSupport is a favourite RAT, and ET files its check-in under
 * INFO, not MALWARE, precisely because it may be sanctioned. So this never calls the server a C2
 * itself; it surfaces the session for an analyst to confirm. When another check has already made
 * the server a C2 (a rule, a RAT's install chain, a suspicion), it points to that answer and its
 * family instead of asking.
 *
 * <p>Found in the 2026-11-10 NetSupport RAT exercise, where the only IDS hit was "ET INFO NetSupport
 * Remote Admin Checkin" to 93.152.209.36, and nothing else in the answers mentioned it.
 *
 * <p>Read from the IDS alerts already on the board. Rules about DNS lookups are skipped: their
 * external endpoint is the resolver, not the tool's server. Rules from ET MALWARE are left to the
 * C2 question, which already treats them as C2.
 */
@Component
public class RemoteAccessQuestion implements StandardQuestion {

  static final String QUESTION = "remote-access";

  @Override
  public String question() {
    return QUESTION;
  }

  @Override
  public Set<Category> categories() {
    return Set.of(Category.REMOTE_ACCESS_SERVER, Category.COMMAND_AND_CONTROL);
  }

  @Override
  public List<Answer> answer(CaseKnowledge board) {
    // (host, tool, external) -> the alerts that showed it
    Map<List<String>, List<String>> sessions = new LinkedHashMap<>();
    Map<List<String>, java.util.Set<String>> convs = new LinkedHashMap<>();
    for (Finding f : java.util.stream.Stream.concat(
        board.findingsOfCategory("ids-alert").stream(),
        board.findingsOfCategory(com.tracepcap.knowledge.contributor.RemoteAccessAppContributor.REMOTE_ACCESS_APP).stream()).toList()) {
      String tool =
          f.attributes().get("tool") instanceof String t
              ? t
              : com.tracepcap.knowledge.contributor.RemoteAccessTools.toolIn(f.summary());
      if (tool == null) continue;
      String alert = f.summary();
      EntityRef host = null;
      EntityRef external = null;
      for (EntityRef r : f.concerns()) {
        if (r.type() == EntityType.HOST) host = r;
        else if (r.type() == EntityType.EXTERNAL_SERVICE) external = r;
      }
      if (host == null || external == null) continue;
      sessions.computeIfAbsent(List.of(host.key(), tool, external.key()), k -> new ArrayList<>()).add(alert);
      convs.computeIfAbsent(List.of(host.key(), tool, external.key()), k -> new java.util.LinkedHashSet<>())
          .addAll(f.evidence());
    }

    // Servers another check already concluded are a C2 (#1262): the session isn't then a tool to
    // confirm, and saying so beside a C2 answer read as a contradiction.
    Map<String, C2Basis> c2s = new LinkedHashMap<>();
    for (com.tracepcap.knowledge.spi.Relationship r : board.relationshipsWithPredicate("c2-of")) {
      C2Basis b = c2s.computeIfAbsent(r.from().key(), k -> new C2Basis());
      b.families.add(r.to().key());
      b.strength = Math.max(b.strength, strengthOf(r.attributes().get("corroboration")));
    }

    List<Answer> answers = new ArrayList<>();
    sessions.forEach((key, alerts) -> {
      String host = key.get(0), tool = key.get(1), external = key.get(2);
      Map<String, Object> attrs = new LinkedHashMap<>();
      attrs.put("host", host);
      attrs.put("tool", tool);
      attrs.put("external", external);
      Map<String, Object> server =
          board.entity(EntityRef.external(external)).map(e -> e.attributes()).orElse(Map.of());
      Object first = server.get("firstSeen");
      if (first != null) attrs.put("firstSeen", first);
      List<String> basis = new ArrayList<>(alerts.stream().distinct().toList());
      // Counts of the records kept, saying so, with the true total, once they were cut (#1284).
      String requests = IdsAlertRecordContributor.requestsLine(server);
      if (requests != null) {
        IdsAlertRecordContributor.putRequests(server, attrs);
        basis.add(requests);
        if (server.get(IdsAlertRecordContributor.ALERT_RECORDS_KEPT) != null) {
          basis.add(IdsAlertRecordContributor.alertSpan(server));
        }
      }
      C2Basis c2 = c2s.get(external);
      if (c2 != null) attrs.put("concludedC2", c2.kind());
      answers.add(
          new Answer(
              QUESTION,
              host + " runs " + tool + ", talking to " + external
                  + " outside the network"
                  + (first != null
                      ? " since "
                          + com.tracepcap.knowledge.contributor.TrafficContributor.readable(first)
                      : "")
                  + ". " + verdict(c2s.get(external)),
              Grade.INFERRED,
              List.of(EntityRef.host(host), EntityRef.external(external)),
              basis,
              attrs).withDerivation(withC2(new com.tracepcap.knowledge.spi.Step(
                  host + " ran " + tool + " to " + external + ", outside the network: "
                      + String.join("; ", alerts.stream().distinct().toList()) + ".",
                  Derivations.RULE_REMOTE_ACCESS, Grade.INFERRED,
                  new ArrayList<>(convs.getOrDefault(key, java.util.Set.of()))), external, c2)));
    });
    return answers;
  }

  /** How firmly another check made a server a C2: by rule, by a RAT's install chain, or suspected. */
  static final class C2Basis {
    final java.util.Set<String> families = new java.util.LinkedHashSet<>();
    int strength;

    String kind() {
      return strength >= 2 ? "c2" : strength == 1 ? "install-chain" : "suspected";
    }
  }

  /** A rule (no corroboration) is firmest, then the install chain, then a suspicion. */
  static int strengthOf(Object corroboration) {
    if (corroboration == null) return 2;
    if ("suspected-c2".equals(corroboration)) return 0;
    return 1;
  }

  /** The families, named ones first, without a tool's "(unsanctioned use)" qualifier. */
  static String families(C2Basis c2) {
    List<String> named = new ArrayList<>();
    boolean unidentified = false;
    for (String f : c2.families) {
      if (EntityRef.UNIDENTIFIED_MALWARE.equals(f)) unidentified = true;
      else named.add(f.replaceAll("\\s*\\([^)]*\\)$", ""));
    }
    if (named.isEmpty()) return unidentified ? "unidentified malware" : "malware";
    return String.join(" and ", named.stream().distinct().toList());
  }

  /**
   * What the analyst should do with the session: confirm it's sanctioned, or, when the server is
   * already a C2, read that answer, worded no more firmly than it is.
   */
  static String verdict(C2Basis c2) {
    if (c2 == null) {
      return "IT uses remote-access tools, and so do attackers: confirm this one is sanctioned.";
    }
    String who = families(c2);
    return switch (c2.kind()) {
      case "c2" -> "The command & control answer concludes this server is a C2 for " + who
          + ", so this isn't a sanctioned install.";
      case "install-chain" -> "The command & control answer treats this server as a C2 for " + who
          + " from how the tool was installed, so this probably isn't a sanctioned install.";
      default -> "The command & control answer suspects this server is a C2 for " + who
          + ", so treat the session as unsanctioned unless IT confirms it.";
    };
  }

  /** The session's step, then the C2 conclusion the headline relies on, when there is one. */
  private static List<com.tracepcap.knowledge.spi.Step> withC2(
      com.tracepcap.knowledge.spi.Step session, String external, C2Basis c2) {
    if (c2 == null) return List.of(session);
    return List.of(session, com.tracepcap.knowledge.spi.Step.of(
        external + " is " + (c2.kind().equals("suspected") ? "a suspected" : "a") + " C2 for " + families(c2)
            + " (the command & control answer shows how).",
        null, Grade.INFERRED));
  }
}
