package com.tracepcap.analysis.spi;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Re-scores a capture's hosts after its detection-rule results changed (#925): each host's stored
 * score board takes back its old rule votes and counts the current ones. Implemented by the
 * {@code analysis} module, which owns the classifications; called by {@code signatures}.
 *
 * <ul>
 *   <li>A machine verdict whose winner changes is updated, with the change recorded on the host
 *       (from what, when, by whom, which rules) and in the audit log.
 *   <li>An analyst's label is never changed. When the machine's winner changes to something other
 *       than the label, the label is flagged stale with the reason.
 * </ul>
 */
public interface RuleVoteRescorer {

  /** One host whose machine device type changed. */
  record Change(UUID fileId, String ip, String from, String to, List<String> rules) {}

  record Outcome(List<Change> changes, int staleLabels) {
    public static final Outcome NONE = new Outcome(List.of(), 0);
  }

  /** {@code votes}: the current rule votes, by host IP. Joins the caller's transaction. */
  Outcome rescore(UUID fileId, Map<String, List<ClassificationHint>> votes, String actor);
}
