package com.tracepcap.knowledge.question;

import com.tracepcap.knowledge.contributor.LateralMovementContributor;
import com.tracepcap.knowledge.contributor.TrafficContributor;
import com.tracepcap.knowledge.spi.Answer;
import com.tracepcap.knowledge.spi.CaseKnowledge;
import com.tracepcap.knowledge.spi.EntityRef;
import com.tracepcap.knowledge.spi.Finding;
import com.tracepcap.knowledge.spi.Grade;
import com.tracepcap.knowledge.spi.StandardQuestion;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.stereotype.Component;

/**
 * "Did one host make another run something?" (#1266). One answer per pair of hosts, from the
 * lateral-movement findings: a service created remotely (how PsExec and smbexec run a command), a
 * scheduled task registered, a WMI method called, an executable copied to an admin share, or a
 * directory replication asked by a host that isn't a domain controller (DCSync).
 *
 * <p>Administrators do the first four too (software deployment, remote support), so the answer says
 * what happened and asks for it to be confirmed; it never names an attacker or a tool. Routine
 * domain traffic (SYSVOL and group-policy reads, share and user enumeration) never reaches it: the
 * contributor doesn't post it.
 */
@Component
public class LateralMovementQuestion implements StandardQuestion {

  static final String QUESTION = "lateral-movement";

  /** Most telling first: it leads the headline. */
  private static final List<String> ORDER = List.of(
      LateralMovementContributor.DCSYNC,
      LateralMovementContributor.REMOTE_SERVICE,
      LateralMovementContributor.SCHEDULED_TASK,
      LateralMovementContributor.WMI_EXEC,
      LateralMovementContributor.ADMIN_SHARE_COPY);

  @Override
  public String question() {
    return QUESTION;
  }

  @Override
  public List<Answer> answer(CaseKnowledge board) {
    Map<List<String>, List<Finding>> pairs = new LinkedHashMap<>();
    for (Finding f : board.findingsOfCategory(LateralMovementContributor.LATERAL_MOVEMENT)) {
      if (!(f.attributes().get("client") instanceof String c) || !(f.attributes().get("server") instanceof String s)) continue;
      pairs.computeIfAbsent(List.of(c, s), k -> new ArrayList<>()).add(f);
    }
    List<Answer> answers = new ArrayList<>();
    pairs.forEach((pair, findings) -> {
      String client = pair.get(0), server = pair.get(1);
      findings.sort(java.util.Comparator.comparingInt(f -> ORDER.indexOf(technique(f))));
      Set<String> techniques = new LinkedHashSet<>();
      Set<String> basis = new LinkedHashSet<>();
      String first = null;
      for (Finding f : findings) {
        techniques.add(technique(f));
        if (f.attributes().get("operations") instanceof List<?> l) l.forEach(x -> basis.add(String.valueOf(x)));
        Object t = f.attributes().get("firstSeen");
        if (t instanceof String ts && (first == null || ts.compareTo(first) < 0)) first = ts;
      }
      Map<String, Object> attrs = new LinkedHashMap<>();
      attrs.put("client", client);
      attrs.put("server", server);
      attrs.put("techniques", List.copyOf(techniques));
      if (first != null) attrs.put("firstSeen", first);
      answers.add(new Answer(
          QUESTION,
          headline(client, server, techniques, first),
          Grade.MEASURED,
          List.of(EntityRef.host(client), EntityRef.host(server)),
          List.copyOf(basis),
          attrs).withDerivation(findings.stream()
              .map(f -> new com.tracepcap.knowledge.spi.Step(
                  client + " → " + server + ": " + (f.attributes().get("operations") instanceof List<?> l
                      ? String.join("; ", l.stream().map(String::valueOf).toList()) : f.summary()) + ".",
                  Derivations.lateralRule(technique(f)), Grade.MEASURED, f.evidence()))
              .toList()));
    });
    return answers;
  }

  private static String technique(Finding f) {
    return String.valueOf(f.attributes().get("technique"));
  }

  static String headline(String client, String server, Set<String> techniques, String first) {
    List<String> did = new ArrayList<>();
    String why = null;
    for (String t : techniques) {
      String meaning = switch (t) {
        case LateralMovementContributor.DCSYNC -> {
          did.add("asked " + server + " to replicate directory data, and isn't seen acting as a domain"
              + " controller in this capture");
          yield "That is what DCSync looks like: it copies the domain's password hashes.";
        }
        case LateralMovementContributor.REMOTE_SERVICE -> {
          did.add("created a service on " + server + " over RPC");
          yield "That is how PsExec and smbexec run a command on another machine.";
        }
        case LateralMovementContributor.SCHEDULED_TASK -> {
          did.add("registered a scheduled task on " + server);
          yield "A remote task runs a command on that machine.";
        }
        case LateralMovementContributor.WMI_EXEC -> {
          did.add("called a WMI method on " + server);
          yield "That is how a process is started on another machine.";
        }
        case LateralMovementContributor.ADMIN_SHARE_COPY -> {
          did.add("copied a program to an admin share on " + server);
          yield null;
        }
        default -> null;
      };
      if (why == null) why = meaning; // the most telling technique's, as they come in that order
    }
    String when = first != null ? " (from " + TrafficContributor.readable(first) + ")" : "";
    return client + " " + join(did) + when + "." + (why != null ? " " + why : "")
        + " Confirm an administrator did this.";
  }

  private static String join(List<String> parts) {
    if (parts.size() <= 1) return parts.isEmpty() ? "acted on another host" : parts.get(0);
    return String.join(", ", parts.subList(0, parts.size() - 1)) + " and " + parts.get(parts.size() - 1);
  }
}
