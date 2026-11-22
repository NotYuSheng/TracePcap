package com.tracepcap.knowledge.question;

import com.tracepcap.knowledge.spi.Answer;
import com.tracepcap.knowledge.spi.CaseKnowledge;
import com.tracepcap.knowledge.spi.EntityRef;
import com.tracepcap.knowledge.spi.EntityType;
import com.tracepcap.knowledge.spi.Finding;
import com.tracepcap.knowledge.spi.Grade;
import com.tracepcap.knowledge.spi.StandardQuestion;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

/**
 * "Is a remote-access tool talking to the internet?" A remote-admin tool (NetSupport, AnyDesk,
 * ScreenConnect, TeamViewer…) seen checking in to a server outside the network. IT departments use
 * these tools, and so do attackers: NetSupport is a favourite RAT, and ET files its check-in under
 * INFO, not MALWARE, precisely because it may be sanctioned. So this neither calls the server a C2
 * nor names a malware family; it surfaces the session for an analyst to confirm.
 *
 * <p>Found in the 2026-11-10 NetSupport RAT exercise, where the only IDS hit was "ET INFO NetSupport
 * Remote Admin Checkin" to 93.152.209.36, and nothing else in the answers mentioned it.
 *
 * <p>Read from the IDS alerts already on the board. Rules about DNS lookups are skipped: their
 * external endpoint is the resolver, not the tool's server. Rules from ET MALWARE are left to the
 * C2 question, which already treats them as C2.
 */
@Component
public class RemoteAccessQuestion implements StandardQuestion {

  static final String QUESTION = "remote-access";

  /** The tools by the names ET's rules use, with how to show them. */
  private static final Map<String, String> TOOLS = new LinkedHashMap<>();

  static {
    TOOLS.put("netsupport", "NetSupport");
    TOOLS.put("anydesk", "AnyDesk");
    TOOLS.put("screenconnect", "ScreenConnect");
    TOOLS.put("connectwise control", "ScreenConnect");
    TOOLS.put("teamviewer", "TeamViewer");
    TOOLS.put("atera", "Atera");
    TOOLS.put("splashtop", "Splashtop");
    TOOLS.put("rustdesk", "RustDesk");
    TOOLS.put("supremo", "Supremo");
    TOOLS.put("remote utilities", "Remote Utilities");
    TOOLS.put("logmein", "LogMeIn");
    TOOLS.put("simplehelp", "SimpleHelp");
    TOOLS.put("meshcentral", "MeshCentral");
    TOOLS.put("action1", "Action1");
    TOOLS.put("tactical rmm", "Tactical RMM");
    TOOLS.put("kaseya", "Kaseya");
    TOOLS.put("zoho assist", "Zoho Assist");
    TOOLS.put("ninjaone", "NinjaOne");
  }

  private static final Pattern TOOL =
      Pattern.compile(
          "\\b(" + String.join("|", TOOLS.keySet().stream().map(Pattern::quote).toList()) + ")\\b",
          Pattern.CASE_INSENSITIVE);

  /** Rules about a name lookup: the far end is a resolver, not the tool's server. */
  private static final Pattern DNS_RULE =
      Pattern.compile("\\b(DNS (Lookup|Query)|in DNS)\\b", Pattern.CASE_INSENSITIVE);

  @Override
  public String question() {
    return QUESTION;
  }

  @Override
  public List<Answer> answer(CaseKnowledge board) {
    // (host, tool, external) -> the alerts that showed it
    Map<List<String>, List<String>> sessions = new LinkedHashMap<>();
    for (Finding f : board.findingsOfCategory("ids-alert")) {
      String alert = f.summary();
      if (alert == null || alert.contains(" MALWARE ") || DNS_RULE.matcher(alert).find()) continue;
      Matcher m = TOOL.matcher(alert);
      if (!m.find()) continue;
      EntityRef host = null;
      EntityRef external = null;
      for (EntityRef r : f.concerns()) {
        if (r.type() == EntityType.HOST) host = r;
        else if (r.type() == EntityType.EXTERNAL_SERVICE) external = r;
      }
      if (host == null || external == null) continue;
      String tool = TOOLS.get(m.group(1).toLowerCase(Locale.ROOT));
      sessions.computeIfAbsent(List.of(host.key(), tool, external.key()), k -> new ArrayList<>()).add(alert);
    }

    List<Answer> answers = new ArrayList<>();
    sessions.forEach((key, alerts) -> {
      String host = key.get(0), tool = key.get(1), external = key.get(2);
      Map<String, Object> attrs = new LinkedHashMap<>();
      attrs.put("host", host);
      attrs.put("tool", tool);
      attrs.put("external", external);
      Object first =
          board.entity(EntityRef.external(external)).map(e -> e.attributes().get("firstSeen")).orElse(null);
      if (first != null) attrs.put("firstSeen", first);
      answers.add(
          new Answer(
              QUESTION,
              host + " runs " + tool + ", talking to " + external
                  + " outside the network"
                  + (first != null
                      ? " since "
                          + com.tracepcap.knowledge.contributor.TrafficContributor.readable(first)
                      : "")
                  + ". IT uses remote-access tools, and so do attackers:"
                  + " confirm this one is sanctioned.",
              Grade.INFERRED,
              List.of(EntityRef.host(host), EntityRef.external(external)),
              alerts.stream().distinct().toList(),
              attrs));
    });
    return answers;
  }
}
