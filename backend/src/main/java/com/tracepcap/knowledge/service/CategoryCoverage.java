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

  public List<CategoryStatus> coverage(
      UUID fileId, InvestigationReport report, CaptureContextService.CaptureContext context,
      HoneypotRoleService.HoneypotReport honeypots) {
    ConversationLookup.FacetCounts facets = conversations.facetCounts(fileId);
    return withHoneypots(withContext(compute(catalogue.entries(), answeredQuestions(report),
        ruledOutQuestions(report), facets.l7Protocols().keySet(), facets.apps().keySet()), context),
        honeypots);
  }

  /**
   * The Honeypot category from the honeypot role: answered when a host reads as one, open when a
   * host matched a signature but not enough to tell, and ruled out when every server's banners and
   * certificates were read and none matched.
   */
  static List<CategoryStatus> withHoneypots(
      List<CategoryStatus> statuses, HoneypotRoleService.HoneypotReport report) {
    if (report == null) return statuses;
    List<CategoryStatus> out = new ArrayList<>();
    for (CategoryStatus s : statuses) {
      out.add(s.category() == Category.HONEYPOT ? honeypot(report, s.leads()) : s);
    }
    return out;
  }

  private static CategoryStatus honeypot(HoneypotRoleService.HoneypotReport r, List<Lead> leads) {
    Category c = Category.HONEYPOT;
    List<HoneypotRoleService.HostRole> found = r.honeypots();
    if (!found.isEmpty()) {
      return new CategoryStatus(c, Status.ANSWERED, false, String.join("; ", found.stream()
          .map(h -> h.described() + ("HUMAN".equals(h.basis()) ? " (set by an analyst)" : " (inferred)"))
          .toList()), leads);
    }
    var undecided = r.hosts().stream().filter(h -> h.label() == null).toList();
    if (!undecided.isEmpty()) {
      var h = undecided.get(0);
      return new CategoryStatus(c, Status.OPEN, false, h.host() + " points at "
          + (h.honeypot() == null ? "a honeypot" : h.honeypot()) + ", but " + h.reason(), leads);
    }
    if (!r.hosts().isEmpty()) {
      return new CategoryStatus(c, Status.RULED_OUT, false, String.join("; ",
          r.hosts().stream().map(h -> h.described() + " (set by an analyst)").toList()), leads);
    }
    String checked = " (" + r.serversChecked() + (r.serversChecked() == 1 ? " server" : " servers")
        + " checked)";
    if (r.singleSignal() > 0) {
      return new CategoryStatus(c, Status.RULED_OUT, false, "no server showed enough: "
          + r.singleSignal() + " sent" + " only a stock honeypot"
          + " banner, which real servers send too" + checked, leads);
    }
    if (r.serversChecked() > 0) {
      return new CategoryStatus(c, Status.RULED_OUT, false,
          "no server matched a honeypot signature" + checked, leads);
    }
    return new CategoryStatus(c, Status.OPEN, false,
        "no server banners or certificates in this capture to check", leads);
  }

  /**
   * The capture-context categories answered from the capture's context, and the vantage point
   * framing what it hides: traffic between internal hosts doesn't cross an internet uplink. Only
   * when the capture has none: some internal traffic is still there to look at.
   */
  static List<CategoryStatus> withContext(
      List<CategoryStatus> statuses, CaptureContextService.CaptureContext context) {
    if (context == null) return statuses;
    CaptureContextService.VantagePoint v = context.vantage();
    boolean uplink = v != null && CaptureContextService.Vantage.UPLINK.key().equals(v.key());
    List<CategoryStatus> out = new ArrayList<>();
    for (CategoryStatus s : statuses) {
      Category c = s.category();
      if (c == Category.VANTAGE_POINT && v != null) {
        out.add(v.determined()
            ? new CategoryStatus(c, Status.ANSWERED, false,
                v.described() + ("HUMAN".equals(v.basis()) ? " (set by an analyst)" : " (inferred)"),
                List.of())
            : new CategoryStatus(c, Status.OPEN, false, v.reason(), List.of()));
      } else if (c == Category.COMPLETENESS && context.completeness() != null) {
        out.add(new CategoryStatus(c, Status.ANSWERED, false, context.completeness().label(), List.of()));
      } else if (c == Category.TIME_SPAN && context.timeSpan() != null
          && context.timeSpan().label() != null) {
        out.add(new CategoryStatus(c, Status.ANSWERED, false, context.timeSpan().label(), List.of()));
      } else if (c == Category.LATERAL_MOVEMENT && uplink && s.leads().isEmpty()
          && context.internalConversations() == 0
          && (s.status() == Status.OPEN || s.status() == Status.NOT_OBSERVABLE)) {
        out.add(new CategoryStatus(c, Status.NOT_OBSERVABLE, false,
            "taken on the internet uplink, which traffic between internal hosts doesn't cross:"
                + " a capture inside the LAN would show it", List.of()));
      } else {
        out.add(s);
      }
    }
    return out;
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
