package com.tracepcap.knowledge.contributor;

import com.tracepcap.analysis.spi.ConversationLookup.ConversationFacts;
import com.tracepcap.common.net.IpLocality;
import com.tracepcap.knowledge.spi.CaseKnowledgeBuilder;
import com.tracepcap.knowledge.spi.EntityRef;
import com.tracepcap.knowledge.spi.Finding;
import com.tracepcap.knowledge.spi.Grade;
import com.tracepcap.knowledge.spi.Relationship;
import com.tracepcap.knowledge.spi.Severity;
import com.tracepcap.knowledge.spi.KnowledgeContext;
import com.tracepcap.knowledge.spi.KnowledgeContributor;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import com.tracepcap.analysis.spi.IdsRuleMetadata;
import org.springframework.stereotype.Component;

/**
 * Posts Suricata IDS hits as board findings — the other fact the STRRAT demo showed Story mode was
 * missing. Each flagged conversation becomes an {@code ids-alert} finding concerning both endpoints,
 * with a {@code communicates-with} relationship from the internal host to the external service and,
 * where the signature names a family (e.g. STRRAT), a malware entity. "What is the C2?" then becomes
 * a query over these findings, not a metric-based guess.
 */
@Component
public class IdsAlertContributor implements KnowledgeContributor {

  /** The active ruleset's metadata: names a family from the rule's own {@code malware_family} tag. */
  private final IdsRuleMetadata ruleMetadata;

  @org.springframework.beans.factory.annotation.Autowired
  public IdsAlertContributor(IdsRuleMetadata ruleMetadata) {
    this.ruleMetadata = ruleMetadata;
  }

  /** Without a ruleset (tests): families come from the rule message alone. */
  IdsAlertContributor() {
    this(IdsRuleMetadata.NONE);
  }

  /** The sid in a stored alert label, "… (sid:2066606 sev:1)". */
  private static final Pattern SID = Pattern.compile("\\(sid:(\\d+)");

  static final String IDS_ALERT = "ids-alert";
  static final String COMMUNICATES_WITH = "communicates-with";
  static final String C2_OF = "c2-of";

  /**
   * A malware rule about command and control: "Fake Microsoft Teams CnC Payload Request", "… C2
   * Checkin", "… Beacon". Only these make an unnamed C2; an informational or reputation rule (a
   * Spamhaus DROP hit, a PowerShell user agent) never does.
   */
  private static final Pattern C2_RULE =
      Pattern.compile("\\bMALWARE\\b.*\\b(CnC|C2|Check-?in|Beacon(ing)?)\\b", Pattern.CASE_INSENSITIVE);

  /**
   * The token(s) after "MALWARE" in an ET rule name. Group 1 is an all-caps lead token (a family
   * like {@code STRRAT}, or a platform prefix like {@code MSIL}/{@code ELF}); group 2, when the lead
   * is a {@code platform/family} form, is the family after the slash ({@code MSIL/Ramnit} → Ramnit).
   */
  private static final Pattern MALWARE_FAMILY =
      Pattern.compile("\\bMALWARE\\s+([A-Z0-9_]{2,})(?:/([A-Za-z0-9_]{2,}))?\\b");

  /**
   * All-caps lead tokens that follow "MALWARE" in ET rule names but are protocols/categories, not
   * family names (e.g. "ET MALWARE DNS Query ...", "ET MALWARE ABUSE.CH ..."). Without this, the
   * capture would mint a bogus malware entity and a {@code c2-of} edge, turning a benign server into
   * a C2 and its peer into a victim — the exact false positive this layer exists to avoid.
   *
   * <p>This is a heuristic, not a family registry: it suppresses the known-generic lead tokens and
   * extracts the real family from a {@code platform/family} rule, but a novel all-caps generic token
   * or a lowercase platform prefix ("Win32/Foo") is not perfectly handled. A false family is worse
   * than a missed one here, so anything ambiguous is dropped rather than guessed. A rule-semantics
   * classifier (CnC/Checkin ⇒ C2 vs. informational) is the root-cause follow-up.
   */
  private static final java.util.Set<String> NON_FAMILY_TOKENS =
      java.util.Set.of(
          "DNS", "HTTP", "HTTPS", "TLS", "SSL", "TCP", "UDP", "SMB", "SMTP", "FTP", "IRC", "RDP",
          "URI", "URL", "UA", "CNC", "C2", "GET", "POST", "JA3", "OS", "IP", "ABUSE", "WIN32",
          "WIN64", "X86", "X64", "PDF", "JS", "VBS", "PS1", "APT", "CVE", "USER");


  @Override
  public String name() {
    return "ids-alerts";
  }

  @Override
  public void contribute(KnowledgeContext context, CaseKnowledgeBuilder board) {
    // Externals some rule tied to a named family, and externals only a family-less C2 rule hit.
    java.util.Set<EntityRef> named = new java.util.HashSet<>();
    java.util.Set<EntityRef> unnamedC2 = new java.util.LinkedHashSet<>();
    for (ConversationFacts conv : context.conversationFacts()) {
      List<String> alerts = conv.findings().suricataAlerts();
      if (alerts == null || alerts.isEmpty()) continue;

      String srcIp = conv.flow().srcIp();
      String dstIp = conv.flow().dstIp();
      EntityRef srcRef = endpointRef(srcIp);
      EntityRef dstRef = endpointRef(dstIp);
      if (srcRef == null || dstRef == null) continue;

      // The alert itself is a real observation regardless of direction — always record it.
      for (String alert : alerts) {
        board.addFinding(
            new Finding(
                IDS_ALERT,
                alert,
                Severity.CRITICAL,
                Grade.INFERRED,
                "suricata",
                List.of(srcRef, dstRef),
                List.of(conv.id().toString()),
                Map.of("srcIp", srcIp, "dstIp", dstIp)));
      }

      // C2 attribution needs an unambiguous internal → external direction. If both endpoints are
      // local (an IDS hit on internal/lateral traffic) or both routable, there is no host↔C2 pair
      // to assert — record only the finding above, never a bogus communicates-with / c2-of edge.
      boolean srcLocal = IpLocality.isLocal(srcIp);
      boolean dstLocal = IpLocality.isLocal(dstIp);
      if (srcLocal == dstLocal) continue;

      EntityRef internal = srcLocal ? srcRef : dstRef;
      EntityRef external = srcLocal ? dstRef : srcRef;

      board.addRelationship(
          Relationship.of(internal, COMMUNICATES_WITH, external, Grade.MEASURED, name()));

      for (String alert : alerts) {
        String family = malwareFamily(alert);
        if (family == null && C2_RULE.matcher(alert).find()) unnamedC2.add(external);
        if (family != null) {
          named.add(external);
          EntityRef malwareRef = EntityRef.malware(family);
          board.addEntity(malwareRef);
          // The external endpoint is this malware's C2.
          board.addRelationship(
              Relationship.of(external, C2_OF, malwareRef, Grade.INFERRED, "suricata"));
        }
      }
    }

    // A C2 that no rule names a family for (a "Fake Microsoft Teams CnC" request): still the C2,
    // so the host talking to it is the victim, but no family is claimed. Skipped where a named
    // family already covers the server, so a family-less rule beside a named one adds nothing.
    java.util.Set<String> confirmed = new java.util.HashSet<>();
    named.forEach(e -> confirmed.add(e.key()));
    for (EntityRef external : unnamedC2) {
      confirmed.add(external.key());
      if (named.contains(external)) continue;
      EntityRef unidentified = EntityRef.malware(EntityRef.UNIDENTIFIED_MALWARE);
      board.addEntity(unidentified);
      board.addRelationship(Relationship.of(external, C2_OF, unidentified, Grade.INFERRED, "suricata"));
    }

    // C2s no single alert proves: a chain of weaker signals, each link required (C2Corroboration).
    for (C2Corroboration.Escalation e : C2Corroboration.find(context.conversationFacts(), confirmed)) {
      EntityRef external = EntityRef.external(e.external());
      EntityRef malware =
          EntityRef.malware(e.family() != null ? e.family() : EntityRef.UNIDENTIFIED_MALWARE);
      board.addEntity(malware);
      board.addRelationship(
          new Relationship(external, C2_OF, malware, Grade.INFERRED, "corroboration",
              Map.of(CORROBORATION, e.kind(), "reason", e.reason())));
      board.addFinding(
          new Finding(
              "c2-classification",
              e.reason(),
              Severity.HIGH,
              Grade.INFERRED,
              "corroboration",
              List.of(external, EntityRef.host(e.host())),
              List.of(),
              Map.of(CORROBORATION, e.kind())));
    }
  }

  /** On a c2-of edge made by corroboration: which rule ("suspected-c2", "install-chain"). */
  public static final String CORROBORATION = "corroboration";

  /** A host if internal, an external service if routable; null for a blank/unusable address. */
  private EntityRef endpointRef(String ip) {
    if (ip == null || ip.isBlank()) return null;
    return IpLocality.isLocal(ip) ? EntityRef.host(ip) : EntityRef.external(ip);
  }

  /**
   * The malware family an alert names. When the rule is in the active ruleset, its {@code
   * malware_family} tag decides: ET tags 12,000 of its ~19,500 malware rules, and a
   * rule with metadata but no family tag names none. That fixed "Win32/Lumma Stealer" (no family
   * read) and "W32/Badspace.Backdoor" (a spurious "Badspace" beside WarmCookie). Only a rule the
   * ruleset doesn't know falls back to reading the message.
   */
  String malwareFamily(String alert) {
    if (alert == null) return null;
    Matcher sid = SID.matcher(alert);
    if (sid.find()) {
      var info = ruleMetadata.rule(Long.parseLong(sid.group(1)));
      if (info.isPresent() && info.get().hasMetadata()) {
        return spelledAsInMessage(info.get().malwareFamily(), alert);
      }
    }
    return familyFromMessage(alert);
  }

  /**
   * ET writes some tags in capitals ("WARMCOOKIE"); the message usually spells the name properly
   * ("BadSpace/WarmCookie"), so that spelling is used when the two match ignoring case.
   */
  static String spelledAsInMessage(String family, String alert) {
    if (family == null) return null;
    if (!family.equals(family.toUpperCase(java.util.Locale.ROOT))) return family;
    Matcher w = Pattern.compile("(?i)(?<![A-Za-z0-9])" + Pattern.quote(family) + "(?![A-Za-z0-9])").matcher(alert);
    return w.find() ? w.group() : family;
  }

  private String familyFromMessage(String alert) {
    Matcher m = MALWARE_FAMILY.matcher(alert);
    while (m.find()) {
      // Prefer the family after a platform prefix ("MSIL/Ramnit" → Ramnit); else the lead token.
      String family = m.group(2) != null ? m.group(2) : m.group(1);
      if (!NON_FAMILY_TOKENS.contains(family.toUpperCase(java.util.Locale.ROOT))) return family;
    }
    return null;
  }
}
