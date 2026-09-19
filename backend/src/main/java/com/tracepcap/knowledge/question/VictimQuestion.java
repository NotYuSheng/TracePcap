package com.tracepcap.knowledge.question;

import com.tracepcap.knowledge.spi.Answer;
import com.tracepcap.knowledge.spi.CaseKnowledge;
import com.tracepcap.knowledge.spi.EntityRef;
import com.tracepcap.knowledge.spi.EntityType;
import com.tracepcap.knowledge.spi.Grade;
import com.tracepcap.knowledge.spi.Relationship;
import com.tracepcap.knowledge.spi.StandardQuestion;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.stereotype.Component;

/**
 * "Which host is the victim?" — deterministically: an internal host that talks to a known malware
 * C2 (a {@code communicates-with} edge to an external that a {@code c2-of} edge marks). Keyed on the
 * C2, not on "any host in any IDS alert", so the domain controller a policy alert happens to mention
 * is not mislabelled a victim. Enriched with the signed-in user so the answer is a real lead.
 */
@Component
public class VictimQuestion implements StandardQuestion {

  static final String QUESTION = "victim";

  @Override
  public String question() {
    return QUESTION;
  }

  @Override
  public List<Answer> answer(CaseKnowledge board) {
    Set<EntityRef> c2s = new LinkedHashSet<>();
    for (Relationship c2of : board.relationshipsWithPredicate("c2-of")) {
      c2s.add(c2of.from());
    }
    if (c2s.isEmpty()) return List.of();

    // victim host -> the C2s it was seen contacting (deduped: several communicates-with edges — one
    // per alerted conversation plus the aggregated traffic edge — can name the same C2)
    Map<EntityRef, Set<String>> victims = new LinkedHashMap<>();
    for (Relationship comm : board.relationshipsWithPredicate("communicates-with")) {
      if (comm.from().type() == EntityType.HOST && c2s.contains(comm.to())) {
        victims.computeIfAbsent(comm.from(), k -> new LinkedHashSet<>())
            .add("contacted C2 " + comm.to().key());
      }
    }

    List<Answer> answers = new ArrayList<>();
    victims.forEach((host, basis) -> {
      String user = signedInUser(board, host);
      Map<String, Object> attrs = new LinkedHashMap<>();
      attrs.put("host", host.key());
      if (user != null) attrs.put("signedInUser", user);
      String headline =
          host.key()
              + " — contacted a known malware C2"
              + (user != null ? " (signed in as " + user + ")" : "");
      answers.add(
          new Answer(QUESTION, headline, Grade.INFERRED, List.of(host), new ArrayList<>(basis), attrs));
    });
    return answers;
  }

  private String signedInUser(CaseKnowledge board, EntityRef host) {
    List<Relationship> signedIn = board.relationshipsFrom(host, "signed-in-as");
    return signedIn.isEmpty() ? null : signedIn.get(0).to().key();
  }
}
