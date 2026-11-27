package com.tracepcap.knowledge.question;

import com.tracepcap.knowledge.contributor.HoneypotContributor;
import com.tracepcap.knowledge.spi.Answer;
import com.tracepcap.knowledge.spi.CaseKnowledge;
import com.tracepcap.knowledge.spi.Category;
import com.tracepcap.knowledge.spi.EntityRef;
import com.tracepcap.knowledge.spi.Grade;
import com.tracepcap.knowledge.spi.Relationship;
import com.tracepcap.knowledge.spi.StandardQuestion;
import com.tracepcap.knowledge.spi.Step;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.stereotype.Component;

/**
 * "Did a honeypot talk to a C2?" A decoy that did is recording the attack it was set up for, not
 * infected by it, so it is answered here rather than as a victim ({@link VictimQuestion} leaves
 * honeypots out). The C2 itself is still answered by {@link C2Question}. Its own question key, not
 * {@link HoneypotActivityQuestion}'s, so it answers Command and Control without claiming a scanner.
 */
@Component
public class HoneypotC2Question implements StandardQuestion {

  static final String QUESTION = "honeypot-c2";

  @Override
  public String question() {
    return QUESTION;
  }

  @Override
  public Set<Category> categories() {
    return Set.of(Category.COMMAND_AND_CONTROL);
  }

  @Override
  public List<Answer> answer(CaseKnowledge board) {
    Map<String, String> honeypots = HoneypotContributor.honeypots(board);
    if (honeypots.isEmpty()) return List.of();
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
      steps.add(Step.of(decoy + " is " + HoneypotContributor.article(name)
          + " (the Honeypot answer shows how).", null, Grade.INFERRED));
      for (EntityRef server : servers) {
        steps.add(new Step(decoy + " talked to " + server.key() + ", a known command-and-control server.",
            Derivations.RULE_DECOY_C2, Grade.INFERRED, Derivations.conversationsBetween(board, ref, server)));
      }
      out.add(new Answer(QUESTION,
          decoy + ", " + HoneypotContributor.article(name) + ", contacted the known C2 "
              + HoneypotActivityQuestion.join(c2) + ": the attack it was set up to record, not an infection",
          Grade.INFERRED, List.of(ref),
          c2.stream().map(s -> "contacted C2 " + s).toList(), attrs).withDerivation(steps));
    });
    return out;
  }
}
