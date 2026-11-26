package com.tracepcap.knowledge.service;

import com.tracepcap.analysis.spi.ConversationLookup;
import com.tracepcap.knowledge.spi.Category;
import com.tracepcap.knowledge.spi.EvidenceSource;
import com.tracepcap.knowledge.spi.InvestigationReport;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * Each framework category's status on one capture (docs/architecture/investigation-framework.rst,
 * "The four statuses"): answered, ruled out, open, or not observable, with why, and the traffic in
 * the capture worth a look for it.
 */
@Service
@RequiredArgsConstructor
public class CategoryCoverage {

  /** A category's status on one capture. */
  public enum Status {
    ANSWERED,
    RULED_OUT,
    OPEN,
    NOT_OBSERVABLE
  }

  /** A protocol in this capture worth a look for a category, and its conversations. */
  public record Lead(String label, String shows, String query) {}

  /**
   * One category on one capture.
   *
   * @param unchecked no question covers it yet (still {@link Status#OPEN} when the capture could show
   *     it: a gap in TracePcap isn't a gap in the capture)
   * @param reason why it is not observable, or why it is open with no check; null otherwise
   */
  public record CategoryStatus(
      Category category, Status status, boolean unchecked, String reason, List<Lead> leads) {}

  private final CategoryCatalogue catalogue;
  private final ConversationLookup conversations;

  public List<CategoryStatus> coverage(UUID fileId, InvestigationReport report) {
    ConversationLookup.FacetCounts facets = conversations.facetCounts(fileId);
    return compute(catalogue.entries(), answeredQuestions(report), ruledOutQuestions(report),
        facets.l7Protocols().keySet(), facets.apps().keySet());
  }

  /** The question keys with an answer: every goal answered, and every other answer. */
  static Set<String> answeredQuestions(InvestigationReport report) {
    Set<String> out = new HashSet<>();
    report.outcomes().stream().filter(InvestigationReport.GoalOutcome::answered)
        .forEach(o -> out.add(o.goal().questionKey()));
    report.additional().forEach(a -> out.add(a.question()));
    return out;
  }

  /** The question keys whose candidates were tested and ruled out. */
  static Set<String> ruledOutQuestions(InvestigationReport report) {
    Set<String> out = new HashSet<>();
    report.considered().forEach(c -> out.add(c.question()));
    return out;
  }

  /** Board-free seam: the status rules over plain sets, unit-testable without a capture. */
  static List<CategoryStatus> compute(
      List<CategoryCatalogue.Entry> entries, Set<String> answered, Set<String> ruledOut,
      Set<String> l7Present, Set<String> appsPresent) {
    Present present = new Present(l7Present, appsPresent);
    List<CategoryStatus> out = new ArrayList<>();
    for (CategoryCatalogue.Entry e : entries) {
      Category c = e.category();
      List<Lead> leads = present.leads(CategoryLeads.of(c));
      if (e.questions().stream().anyMatch(answered::contains)) {
        out.add(new CategoryStatus(c, Status.ANSWERED, false, null, leads));
      } else if (!e.questions().isEmpty() && ruledOut.containsAll(e.questions())) {
        // Every check that covers it tested candidates and rejected them. One check ruling out its
        // candidate (a TeamViewer peer) says nothing about the others (no C2 was looked into).
        out.add(new CategoryStatus(c, Status.RULED_OUT, false, null, leads));
      } else if (c.visibility() == Category.Visibility.NEVER
          || c.visibility() == Category.Visibility.RARELY) {
        out.add(new CategoryStatus(c, Status.NOT_OBSERVABLE, e.unchecked(), c.unseenReason(), List.of()));
      } else if (!e.unchecked() && !e.readsAnyTraffic() && leads.isEmpty()
          && e.evidence().stream().noneMatch(q -> present.has(q.source()))) {
        // Not when a lead is present: NTLM speaks to Credential Access even though its only check
        // reads Kerberos, so the category stays open with NTLM to look at.
        out.add(new CategoryStatus(c, Status.NOT_OBSERVABLE, false, missing(e), List.of()));
      } else {
        out.add(new CategoryStatus(c, Status.OPEN, e.unchecked(),
            e.unchecked() ? "no check covers this yet" : null, leads));
      }
    }
    return out;
  }

  /** "no SMB or DCE-RPC in this capture", from the traffic its questions read. */
  private static String missing(CategoryCatalogue.Entry e) {
    List<String> labels = e.evidence().stream().map(q -> q.source().label()).distinct().toList();
    String joined = labels.size() == 1 ? labels.get(0)
        : String.join(", ", labels.subList(0, labels.size() - 1)) + " or " + labels.get(labels.size() - 1);
    return "no " + joined + " in this capture";
  }

  /** The protocols and apps one capture holds, matched the way the Conversations filters take them. */
  private static final class Present {
    private final Map<String, String> l7 = new LinkedHashMap<>();
    private final Map<String, String> apps = new LinkedHashMap<>();

    Present(Set<String> l7Present, Set<String> appsPresent) {
      l7Present.forEach(p -> l7.put(p.toUpperCase(Locale.ROOT), p));
      appsPresent.forEach(a -> apps.put(a.toLowerCase(Locale.ROOT), a));
    }

    boolean has(EvidenceSource s) {
      return !viaL7(s).isEmpty() || !viaApps(s).isEmpty();
    }

    List<String> viaL7(EvidenceSource s) {
      return s.l7().stream().filter(n -> l7.containsKey(n.toUpperCase(Locale.ROOT))).toList();
    }

    List<String> viaApps(EvidenceSource s) {
      return s.apps().stream().map(n -> apps.get(n.toLowerCase(Locale.ROOT)))
          .filter(java.util.Objects::nonNull).toList();
    }

    /**
     * The leads present, each linked to its conversations. The filters combine with AND, so a link
     * uses one: nDPI's name is usually the better net, tshark's when the source says so (TLS, HTTP).
     */
    List<Lead> leads(List<EvidenceSource> sources) {
      List<Lead> out = new ArrayList<>();
      for (EvidenceSource s : sources) {
        List<String> byL7 = viaL7(s);
        List<String> byApp = viaApps(s);
        if (byL7.isEmpty() && byApp.isEmpty()) continue;
        boolean useL7 = !byL7.isEmpty() && (s.byL7() || byApp.isEmpty());
        String query = useL7
            ? "l7Protocols=" + encode(String.join(",", byL7))
            : "apps=" + encode(String.join(",", byApp));
        out.add(new Lead(s.label(), s.shows(), query));
      }
      return out;
    }

    private static String encode(String s) {
      return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20");
    }
  }
}
