package com.tracepcap.knowledge.question;

import com.tracepcap.knowledge.spi.Answer;
import com.tracepcap.knowledge.spi.CaseKnowledge;
import com.tracepcap.knowledge.spi.EntityRef;
import com.tracepcap.knowledge.spi.Finding;
import com.tracepcap.knowledge.spi.Grade;
import com.tracepcap.knowledge.spi.Relationship;
import com.tracepcap.knowledge.spi.StandardQuestion;
import com.tracepcap.knowledge.spi.Category;
import com.tracepcap.knowledge.contributor.IdsAlertRecordContributor;
import com.tracepcap.knowledge.contributor.TrafficContributor;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
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
  public Set<Category> categories() {
    return Set.of(Category.C2_SERVER, Category.COMMAND_AND_CONTROL);
  }

  @Override
  public List<Answer> answer(CaseKnowledge board) {
    // external C2 -> the malware families it serves (deduped: the same family can be named by
    // several rules on one conversation, or recur across conversations)
    Map<EntityRef, Set<String>> c2ToMalware = new LinkedHashMap<>();
    // Servers only corroboration made a C2 (no alert of their own named them): worded "suspected".
    Map<EntityRef, Boolean> suspectedOnly = new LinkedHashMap<>();
    // How each C2 was concluded, for the UI: "rule" (a malware rule named it), or the
    // corroboration kind ("suspected-c2", "install-chain") with its reason.
    Map<EntityRef, Map<String, String>> basisOf = new LinkedHashMap<>();
    for (Relationship c2of : board.relationshipsWithPredicate("c2-of")) {
      c2ToMalware.computeIfAbsent(c2of.from(), k -> new LinkedHashSet<>()).add(c2of.to().key());
      boolean suspected = "suspected-c2".equals(c2of.attributes().get("corroboration"));
      suspectedOnly.merge(c2of.from(), suspected, Boolean::logicalAnd);
      Object kind = c2of.attributes().get("corroboration");
      if (kind == null) basisOf.put(c2of.from(), Map.of("kind", "rule"));
      else
        // The strongest conclusion names the chip, as it does the headline: a rule, then an install
        // chain, then a suspected C2 (only "suspected" when nothing stronger named the server).
        basisOf.merge(
            c2of.from(),
            Map.of("kind", String.valueOf(kind), "reason", String.valueOf(c2of.attributes().getOrDefault("reason", ""))),
            (old, neu) -> "suspected-c2".equals(old.get("kind")) ? neu : old);
    }

    List<Answer> answers = new ArrayList<>();
    c2ToMalware.forEach((c2, families) -> {
      List<EntityRef> subjects = new ArrayList<>();
      subjects.add(c2);
      families.forEach(f -> subjects.add(EntityRef.malware(f)));
      Map<String, Object> attrs = new LinkedHashMap<>();
      attrs.put("address", c2.key());
      // Always a list, so the attribute's JSON type is stable whether one family or several.
      attrs.put("malware", new ArrayList<>(families));
      // Geo attribution (posted by GeoOrgContributor) if present — names where the C2 is hosted.
      String place = geoAttribution(board, c2, attrs);
      Object first = board.entity(c2).map(e -> e.attributes().get("firstSeen")).orElse(null);
      if (first != null) attrs.put("firstSeen", first);
      // From the full alert records (#1265): the requests the alerts fired on, and the alert span.
      Map<String, Object> ent = board.entity(c2).map(e -> e.attributes()).orElse(Map.of());
      List<String> evidence = new ArrayList<>(alertSummaries(board, c2));
      String requests = IdsAlertRecordContributor.requestsLine(ent);
      if (requests != null) {
        IdsAlertRecordContributor.putRequests(ent, attrs);
        evidence.add(requests);
      }
      String span = alertSpan(ent);
      if (span != null) evidence.add(span);
      if (ent.get(IdsAlertRecordContributor.FIRST_ALERT) != null) {
        attrs.put("firstAlert", ent.get(IdsAlertRecordContributor.FIRST_ALERT));
        attrs.put("lastAlert", ent.get(IdsAlertRecordContributor.LAST_ALERT));
      }
      Map<String, String> basis = basisOf.getOrDefault(c2, Map.of("kind", "rule"));
      attrs.put("conclusion", basis.get("kind"));
      if (basis.get("reason") != null && !basis.get("reason").isBlank())
        attrs.put("conclusionReason", basis.get("reason"));
      answers.add(
          new Answer(
              QUESTION,
              c2.key()
                  + (place != null ? " (" + place + ")" : "")
                  + (Boolean.TRUE.equals(suspectedOnly.get(c2)) ? " — suspected C2 for " : " — C2 for ")
                  + String.join(", ", families.stream()
                      .map(f -> EntityRef.UNIDENTIFIED_MALWARE.equals(f)
                          ? (Boolean.TRUE.equals(suspectedOnly.get(c2))
                              ? "unidentified malware"
                              : "unidentified malware (the rule names no family)")
                          : f)
                      .toList())
                  + (first != null
                      ? ", first contacted "
                          + com.tracepcap.knowledge.contributor.TrafficContributor.readable(first)
                      : ""),
              Grade.INFERRED,
              subjects,
              evidence,
              attrs).withDerivation(Derivations.c2(board, c2, families)));
    });
    return answers;
  }

  /**
   * The evidence behind this C2 as the answer's basis: IDS alerts that concern the endpoint, and the
   * stream classifier's finding when the C2 was identified from the beacon's own protocol (which is
   * the only basis when no IDS rule fired).
   */
  private List<String> alertSummaries(CaseKnowledge board, EntityRef external) {
    return Evidence.collapse(
        Stream.concat(
                board.findingsOfCategory("ids-alert").stream(),
                board.findingsOfCategory("c2-classification").stream())
            .filter(f -> f.concerns().contains(external))
            .map(Finding::summary)
            .toList());
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

  /** See {@link IdsAlertRecordContributor#alertSpan}. */
  static String alertSpan(Map<String, Object> ent) {
    return IdsAlertRecordContributor.alertSpan(ent);
  }
}
