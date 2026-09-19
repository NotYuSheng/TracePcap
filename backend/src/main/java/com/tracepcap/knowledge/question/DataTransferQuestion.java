package com.tracepcap.knowledge.question;

import com.tracepcap.knowledge.spi.Answer;
import com.tracepcap.knowledge.spi.CaseKnowledge;
import com.tracepcap.knowledge.spi.Entity;
import com.tracepcap.knowledge.spi.EntityRef;
import com.tracepcap.knowledge.spi.EntityType;
import com.tracepcap.knowledge.spi.Grade;
import com.tracepcap.knowledge.spi.Relationship;
import com.tracepcap.knowledge.spi.StandardQuestion;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.springframework.stereotype.Component;

/**
 * "Is there a large transfer worth reviewing?" — a host that moved a bulk of bytes to an external
 * endpoint whose org is <b>not</b> a known CDN or cloud provider. This is the deterministic version
 * of the mistake the LLM made on the #808 demo: it flagged an ordinary Fastly/GitHub CDN transfer
 * as "covert exfiltration". Here the CDN/cloud orgs are excluded by attribution, so only transfers
 * to a real, non-CDN destination surface — and only for <em>review</em>, never asserted as exfil.
 */
@Component
public class DataTransferQuestion implements StandardQuestion {

  static final String QUESTION = "data-transfer";

  /** Only transfers of at least this size are worth surfacing. */
  static final long BULK_THRESHOLD_BYTES = 5_000_000L;

  /**
   * Distinctive brand substrings safe to match anywhere in the org name (checked against the org and
   * its de-spaced form, so "Level 3 Communications" → "level3" hits).
   */
  // NB: no VPS/IaaS-only providers here (e.g. DigitalOcean) — those routinely host C2 and exfil
  // endpoints, so a bulk transfer to one must still surface for review, not be excluded as "a CDN".
  private static final List<String> CDN_BRAND_SUBSTRINGS =
      List.of(
          "cloudflare", "cloudfront", "fastly", "akamai", "edgecast", "limelight", "cachefly",
          "incapsula", "stackpath", "cdn77", "level3");

  /**
   * Short / ambiguous org tokens matched only as whole words — never as substrings — so "aws" no
   * longer swallows "Kaws Networks" and "meta" no longer swallows "Metatel", which would silently
   * drop a genuine exfil destination from review.
   */
  private static final Set<String> CDN_CLOUD_TOKENS =
      Set.of(
          "aws", "amazon", "google", "microsoft", "azure", "github", "apple", "netflix", "meta",
          "facebook", "lumen", "verizon", "oracle", "cdn");

  @Override
  public String question() {
    return QUESTION;
  }

  @Override
  public List<Answer> answer(CaseKnowledge board) {
    List<Answer> answers = new ArrayList<>();
    for (Relationship r : board.relationshipsWithPredicate("communicates-with")) {
      Object bytesObj = r.attributes().get("bytes");
      if (!(bytesObj instanceof Number)) continue; // only the traffic edges carry a byte count
      long bytes = ((Number) bytesObj).longValue();
      if (bytes < BULK_THRESHOLD_BYTES) continue;
      if (r.from().type() != EntityType.HOST || r.to().type() != EntityType.EXTERNAL_SERVICE) continue;

      String org = attr(board, r.to(), "org");
      if (isCdnOrCloud(org)) continue; // ordinary CDN/cloud traffic — not a finding

      String country = attr(board, r.to(), "country");
      String where = org != null ? org : "an unattributed host";
      if (country != null) where += " (" + country + ")";

      Map<String, Object> attrs = new LinkedHashMap<>();
      attrs.put("host", r.from().key());
      attrs.put("external", r.to().key());
      attrs.put("bytes", bytes);
      if (org != null) attrs.put("org", org);
      if (country != null) attrs.put("country", country);

      answers.add(
          new Answer(
              QUESTION,
              r.from().key()
                  + " sent "
                  + megabytes(bytes)
                  + " to "
                  + r.to().key()
                  + " ("
                  + where
                  + ") — not a known CDN; review for data staging / exfiltration",
              Grade.INFERRED,
              List.of(r.from(), r.to()),
              List.of(megabytes(bytes) + " transferred; external org: " + (org != null ? org : "unknown")),
              attrs));
    }
    return answers;
  }

  private String attr(CaseKnowledge board, EntityRef ref, String key) {
    Entity e = board.entity(ref).orElse(null);
    if (e == null) return null;
    Object v = e.attributes().get(key);
    return v == null ? null : v.toString();
  }

  private boolean isCdnOrCloud(String org) {
    if (org == null) return false; // unattributed — do NOT assume benign; surface it
    String lower = org.toLowerCase(Locale.ROOT);
    String despaced = lower.replace(" ", "");
    for (String brand : CDN_BRAND_SUBSTRINGS) {
      if (lower.contains(brand) || despaced.contains(brand)) return true;
    }
    Set<String> tokens = new HashSet<>(Arrays.asList(lower.split("[^a-z0-9]+")));
    return tokens.stream().anyMatch(CDN_CLOUD_TOKENS::contains);
  }

  private String megabytes(long bytes) {
    return String.format(Locale.ROOT, "%.1f MB", bytes / 1_000_000.0);
  }
}
