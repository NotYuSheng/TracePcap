package com.tracepcap.knowledge.question;

import com.tracepcap.knowledge.spi.Answer;
import com.tracepcap.knowledge.spi.CaseKnowledge;
import com.tracepcap.knowledge.spi.EntityRef;
import com.tracepcap.knowledge.spi.Finding;
import com.tracepcap.knowledge.spi.Grade;
import com.tracepcap.knowledge.spi.Relationship;
import com.tracepcap.knowledge.spi.StandardQuestion;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * "What is the command-and-control server?" — an external endpoint identified as a malware C2 by a
 * {@code c2-of} edge (posted when an IDS signature named a family). Deliberately keyed on that edge,
 * not on "any external in any IDS alert": informational/policy alerts must not surface a benign CDN
 * as a C2 — the precision a deterministic check buys over the LLM's volume-based guessing.
 */
@Component
public class C2Question implements StandardQuestion {

  static final String QUESTION = "c2";

  @Override
  public String question() {
    return QUESTION;
  }

  @Override
  public List<Answer> answer(CaseKnowledge board) {
    // external C2 -> the malware families it serves
    Map<EntityRef, List<String>> c2ToMalware = new LinkedHashMap<>();
    for (Relationship c2of : board.relationshipsWithPredicate("c2-of")) {
      c2ToMalware.computeIfAbsent(c2of.from(), k -> new ArrayList<>()).add(c2of.to().key());
    }

    List<Answer> answers = new ArrayList<>();
    c2ToMalware.forEach((c2, families) -> {
      List<EntityRef> subjects = new ArrayList<>();
      subjects.add(c2);
      families.forEach(f -> subjects.add(EntityRef.malware(f)));
      Map<String, Object> attrs = new LinkedHashMap<>();
      attrs.put("address", c2.key());
      attrs.put("malware", families.size() == 1 ? families.get(0) : families);
      // Geo attribution (posted by GeoOrgContributor) if present — names where the C2 is hosted.
      String place = geoAttribution(board, c2, attrs);
      answers.add(
          new Answer(
              QUESTION,
              c2.key()
                  + (place != null ? " (" + place + ")" : "")
                  + " — C2 for "
                  + String.join(", ", families),
              Grade.INFERRED,
              subjects,
              alertSummaries(board, c2),
              attrs));
    });
    return answers;
  }

  /** The IDS alert summaries that concern this external endpoint, as the answer's basis. */
  private List<String> alertSummaries(CaseKnowledge board, EntityRef external) {
    return board.findingsOfCategory("ids-alert").stream()
        .filter(f -> f.concerns().contains(external))
        .map(Finding::summary)
        .toList();
  }

  /**
   * Reads the geo attributes another contributor posted on this external entity, copies them into
   * the answer's attributes, and returns a short "country · org" label for the headline (or null).
   */
  private String geoAttribution(CaseKnowledge board, EntityRef external, Map<String, Object> attrs) {
    var entity = board.entity(external).orElse(null);
    if (entity == null) return null;
    Object country = entity.attributes().get("country");
    Object org = entity.attributes().get("org");
    if (country != null) attrs.put("country", country);
    if (org != null) attrs.put("org", org);
    if (country != null && org != null) return country + " · " + org;
    if (org != null) return org.toString();
    if (country != null) return country.toString();
    return null;
  }
}

