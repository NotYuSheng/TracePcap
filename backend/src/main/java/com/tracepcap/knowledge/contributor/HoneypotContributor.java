package com.tracepcap.knowledge.contributor;

import com.tracepcap.analysis.spi.ConversationLookup;
import com.tracepcap.analysis.spi.ConversationLookup.HostPair;
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
          List.of(EntityRef.host(h.host())), List.of(), attrs));
    }

    ConversationLookup lookup = conversations.getIfAvailable();
    if (lookup == null) return;
    contacts(lookup.hostPairs(context.fileId()), names).forEach((host, c) -> {
      Map<String, Object> attrs = new LinkedHashMap<>();
      attrs.put("host", host);
      attrs.put("honeypots", Map.copyOf(c.reached));
      attrs.put("conversations", c.conversations);
      List<EntityRef> concerns = new java.util.ArrayList<>();
      concerns.add(EntityRef.host(host));
      c.reached.keySet().forEach(ip -> concerns.add(EntityRef.host(ip)));
      board.addFinding(new Finding(CONTACT,
          host + " opened " + c.conversations + " conversation" + (c.conversations == 1 ? "" : "s")
              + " to " + String.join(", ", c.reached.keySet()),
          Severity.MEDIUM, Grade.INFERRED, name(), concerns, List.of(), attrs));
    });
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
