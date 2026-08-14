package com.tracepcap.story.service;

import com.tracepcap.story.dto.InvestigationQuery;
import lombok.extern.slf4j.Slf4j;

/**
 * Repairs of model-authored queries, kept in one place so each one states what it corrects and
 * whether schema-constrained generation has made it unnecessary (#623).
 *
 * <p>These were hard-won against real local-model behaviour, not speculation, so none is deleted on
 * the strength of the constrained path being *expected* to behave. The split is by what a JSON
 * schema can actually enforce:
 *
 * <ul>
 *   <li><b>Byte bounds</b> — the model passed a host's aggregate total into a per-conversation
 *       bound, which matches nothing, so the bound was dropped whenever it appeared beside {@code
 *       srcIp} or {@code riskType}. The constrained tool spells the semantics out in the field
 *       description at the point of generation, so its bounds are honoured; the free-text path,
 *       where the model only ever saw an example object, still gets the drop.
 *   <li><b>Unknown-app sentinels</b> — applied on both paths. A schema constrains a field's
 *       <em>type</em>, not its vocabulary: {@code appName} is a string either way, and "unknown"
 *       stays as expressible under the tool as it was in free text. Nothing about tool calling
 *       retires this one.
 * </ul>
 */
@Slf4j
public final class InvestigationQuerySanitizer {

  private InvestigationQuerySanitizer() {}

  /**
   * A query ready to build a Specification from.
   *
   * @param query the query with unusable filters removed
   * @param appNameIsNull match conversations whose app is unidentified — distinct from {@code
   *     appName == null}, which means "do not filter on app at all"
   */
  public record SanitizedQuery(InvestigationQuery query, boolean appNameIsNull) {}

  /**
   * @param source the query as the model wrote it
   * @param schemaConstrained whether it arrived through a schema-constrained tool call
   */
  public static SanitizedQuery sanitize(InvestigationQuery source, boolean schemaConstrained) {
    InvestigationQuery q = copyOf(source);
    boolean appNameIsNull = false;

    if (q.getAppName() != null && isUnknownAppSentinel(q.getAppName())) {
      appNameIsNull = true;
      q.setAppName(null);
    }

    // Per-conversation bounds beside a filter the model tends to reason about in aggregate.
    boolean byteBoundLikelyAggregate = q.getSrcIp() != null || q.getRiskType() != null;
    if (!schemaConstrained && byteBoundLikelyAggregate) {
      if (q.getMinBytes() != null || q.getMaxBytes() != null) {
        log.debug(
            "Dropping byte bounds on free-text query '{}': likely an aggregate total, which would"
                + " match no single conversation",
            q.getId());
      }
      q.setMinBytes(null);
      q.setMaxBytes(null);
    }

    return new SanitizedQuery(q, appNameIsNull);
  }

  /**
   * Whether the query constrains anything. A query with no filters left matches the whole capture,
   * which is not evidence — it is the dataset.
   */
  public static boolean isCatchAll(SanitizedQuery sanitized) {
    InvestigationQuery q = sanitized.query();
    return !sanitized.appNameIsNull()
        && q.getSrcIp() == null
        && q.getDstIp() == null
        && q.getDstPort() == null
        && q.getProtocol() == null
        && q.getAppName() == null
        && q.getCategory() == null
        && q.getHasRisks() == null
        && q.getHasTlsAnomaly() == null
        && q.getRiskType() == null
        && q.getMinBytes() == null
        && q.getMaxBytes() == null
        && q.getMinFlows() == null;
  }

  /** The strings models reach for when they mean "nDPI could not identify this". */
  private static boolean isUnknownAppSentinel(String appName) {
    String value = appName.trim();
    return value.isEmpty()
        || value.equalsIgnoreCase("UNKNOWN_APP")
        || value.equalsIgnoreCase("unknown")
        || value.equalsIgnoreCase("null");
  }

  private static InvestigationQuery copyOf(InvestigationQuery q) {
    return InvestigationQuery.builder()
        .id(q.getId())
        .label(q.getLabel())
        .srcIp(q.getSrcIp())
        .dstIp(q.getDstIp())
        .dstPort(q.getDstPort())
        .protocol(q.getProtocol())
        .appName(q.getAppName())
        .category(q.getCategory())
        .hasRisks(q.getHasRisks())
        .hasTlsAnomaly(q.getHasTlsAnomaly())
        .riskType(q.getRiskType())
        .minBytes(q.getMinBytes())
        .maxBytes(q.getMaxBytes())
        .minFlows(q.getMinFlows())
        .build();
  }
}
