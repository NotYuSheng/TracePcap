package com.tracepcap.knowledge.contributor;

import com.tracepcap.analysis.spi.ConversationLookup;
import com.tracepcap.analysis.spi.ConversationLookup.HostPair;
import com.tracepcap.common.net.IpLocality;
import com.tracepcap.knowledge.service.HoneypotRoleService;
import com.tracepcap.knowledge.service.HoneypotRoleService.HostRole;
import com.tracepcap.knowledge.spi.CaseKnowledge;
import com.tracepcap.knowledge.spi.CaseKnowledgeBuilder;
import com.tracepcap.knowledge.spi.EntityRef;
import com.tracepcap.knowledge.spi.Finding;
import com.tracepcap.knowledge.spi.Grade;
import com.tracepcap.knowledge.spi.KnowledgeContext;
import com.tracepcap.knowledge.spi.KnowledgeContributor;
import com.tracepcap.knowledge.spi.Severity;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Component;

/**
 * Posts the capture's honeypots to the board, and who reached them, so the questions can read them
 * (docs/architecture/investigation-framework.rst, "How a honeypot changes other answers"): a decoy
 * that talks to a C2 isn't a victim, a file it fetches is the catch, and whoever connects to it is
 * scanning or attacking, since a decoy has no real users.
 *
 * <ul>
 *   <li>{@value #HONEYPOT}: one per host that reads as a honeypot, inferred or set by an analyst.
 *       Attributes: {@code host}, {@code name} (Cowrie, or the analyst's label), {@code basis}.
 *   <li>{@value #CONTACT}: one per host that opened conversations to a honeypot. Attributes:
 *       {@code host} (the one that reached it), {@code honeypots} (address → name), {@code
 *       conversations} (how many it opened to them).
 * </ul>
 */
@Component
public class HoneypotContributor implements KnowledgeContributor {

  public static final String HONEYPOT = "honeypot";

  public static final String CONTACT = "honeypot-contact";

  /**
   * Hosts that reached a decoy posted to the board, the busiest first: an internet-facing decoy can
   * draw tens of thousands of scanners. The questions only list a few of them anyway.
   */
  static final int MAX_CONTACTS = 500;

  /** Looked up when needed: a context without them (a test, a slice) still works. */
  private final ObjectProvider<HoneypotRoleService> roles;

  private final ObjectProvider<ConversationLookup> conversations;

  public HoneypotContributor(
      ObjectProvider<HoneypotRoleService> roles, ObjectProvider<ConversationLookup> conversations) {
    this.roles = roles;
    this.conversations = conversations;
  }

  @Override
  public String name() {
    return "honeypots";
  }

  @Override
  public void contribute(KnowledgeContext context, CaseKnowledgeBuilder board) {
    HoneypotRoleService service = roles.getIfAvailable();
    if (service == null) return;
    List<HostRole> honeypots = service.forFile(context.fileId()).honeypots();
    if (honeypots.isEmpty()) return;

    Map<String, String> names = new LinkedHashMap<>();
    for (HostRole h : honeypots) {
      String name = name(h);
      names.put(h.host(), name);
      Map<String, Object> attrs = new LinkedHashMap<>();
      attrs.put("host", h.host());
      attrs.put("name", name);
      attrs.put("basis", h.basis());
      board.addFinding(new Finding(HONEYPOT, h.described(), Severity.INFO,
          "HUMAN".equals(h.basis()) ? Grade.REPORTED : Grade.INFERRED, name(),
          List.of(ref(h.host())), List.of(), attrs));
    }

    ConversationLookup lookup = conversations.getIfAvailable();
    if (lookup == null) return;
    Map<String, Contact> contacts = contacts(lookup.hostPairs(context.fileId()), names);
    contacts.entrySet().stream()
        .sorted(java.util.Comparator.comparingLong((Map.Entry<String, Contact> e) -> e.getValue().conversations)
            .reversed().thenComparing(Map.Entry::getKey))
        .limit(MAX_CONTACTS)
        .forEach(e -> board.addFinding(contactFinding(e.getKey(), e.getValue())));
  }

  /** "198.51.100.101 reached 198.51.100.22 in 6 conversations", the host first among its concerns. */
  private Finding contactFinding(String host, Contact c) {
    Map<String, Object> attrs = new LinkedHashMap<>();
    attrs.put("host", host);
    attrs.put("honeypots", Map.copyOf(c.reached));
    attrs.put("conversations", c.conversations);
    List<EntityRef> concerns = new java.util.ArrayList<>();
    concerns.add(ref(host));
    c.reached.keySet().forEach(ip -> concerns.add(ref(ip)));
    return new Finding(CONTACT,
        host + " reached " + String.join(", ", c.reached.keySet()) + " in " + c.conversations
            + " conversation" + (c.conversations == 1 ? "" : "s"),
        Severity.MEDIUM, Grade.INFERRED, name(), concerns, List.of(), attrs);
  }

  /** Who reached a honeypot. */
  static final class Contact {
    final Map<String, String> reached = new TreeMap<>();
    long conversations;
  }

  /**
   * Every host that opened a conversation to a honeypot, and which ones. Another honeypot reaching
   * one doesn't count (decoys answer each other's probes in a lab), and neither does a conversation
   * the honeypot opened: that is its own reply or a scan back.
   *
   * <p>Only conversations with a known opener count, in practice TCP with a handshake. One with
   * none (UDP, ARP, a connection already open when the capture began) can't say who reached whom:
   * a decoy's own DNS lookups would make the resolver read as a scanner. A UDP-only sweep (SIP,
   * SNMP) is missed for now.
   */
  static Map<String, Contact> contacts(List<HostPair> pairs, Map<String, String> honeypots) {
    Map<String, Contact> out = new TreeMap<>();
    for (HostPair p : pairs) {
      add(out, p.b(), p.a(), p.openedByB(), honeypots);
      add(out, p.a(), p.b(), p.openedByA(), honeypots);
    }
    return out;
  }

  private static void add(Map<String, Contact> out, String opener, String target, long opened,
      Map<String, String> honeypots) {
    if (opened <= 0 || !honeypots.containsKey(target) || honeypots.containsKey(opener)) return;
    Contact c = out.computeIfAbsent(opener, k -> new Contact());
    c.reached.put(target, honeypots.get(target));
    c.conversations += opened;
  }

  /** A host inside the network, or one outside it: the board types them apart. */
  private static EntityRef ref(String ip) {
    return IpLocality.isLocal(ip) ? EntityRef.host(ip) : EntityRef.external(ip);
  }

  /** "a Cowrie honeypot", "an Internal sensor": an analyst's own label reads right too. */
  public static String article(String name) {
    return (name != null && !name.isEmpty() && "aeiouAEIOU".indexOf(name.charAt(0)) >= 0 ? "an " : "a ")
        + name;
  }

  /** "Cowrie honeypot", "honeypot", or the analyst's own label ("T-Pot sensor"). */
  static String name(HostRole h) {
    if (!HoneypotRoleService.HONEYPOT.equals(h.label())) return h.label();
    return h.honeypot() == null ? "honeypot" : h.honeypot() + " honeypot";
  }

  /** The board's honeypots: address → name ("Cowrie honeypot"). */
  public static Map<String, String> honeypots(CaseKnowledge board) {
    Map<String, String> out = new LinkedHashMap<>();
    for (Finding f : board.findingsOfCategory(HONEYPOT)) {
      out.put(String.valueOf(f.attributes().get("host")), String.valueOf(f.attributes().get("name")));
    }
    return out;
  }
}
