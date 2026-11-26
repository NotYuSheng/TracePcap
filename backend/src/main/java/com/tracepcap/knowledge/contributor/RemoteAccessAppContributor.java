package com.tracepcap.knowledge.contributor;

import com.tracepcap.analysis.spi.ConversationLookup.ConversationFacts;
import com.tracepcap.common.net.IpLocality;
import com.tracepcap.knowledge.spi.CaseKnowledgeBuilder;
import com.tracepcap.knowledge.spi.EntityRef;
import com.tracepcap.knowledge.spi.Finding;
import com.tracepcap.knowledge.spi.Grade;
import com.tracepcap.knowledge.spi.KnowledgeContext;
import com.tracepcap.knowledge.spi.KnowledgeContributor;
import com.tracepcap.knowledge.spi.Severity;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.stereotype.Component;

/**
 * Remote-control sessions nDPI recognises by itself (TeamViewer, AnyDesk, Radmin, NoMachine), so
 * the remote-access answer doesn't depend on Suricata being switched on. One finding per host,
 * tool and outside server.
 */
@Component
public class RemoteAccessAppContributor implements KnowledgeContributor {

  public static final String REMOTE_ACCESS_APP = "remote-access-app";

  @Override
  public String name() {
    return "remote-access-apps";
  }

  @Override
  public void contribute(KnowledgeContext context, CaseKnowledgeBuilder board) {
    Set<List<String>> seen = new LinkedHashSet<>();
    for (ConversationFacts c : context.conversationFacts()) {
      String tool = RemoteAccessTools.toolForApp(c.findings().appName());
      if (tool == null) continue;
      String a = c.flow().srcIp(), b = c.flow().dstIp();
      if (a == null || b == null || IpLocality.isLocal(a) == IpLocality.isLocal(b)) continue;
      String host = IpLocality.isLocal(a) ? a : b;
      String external = IpLocality.isLocal(a) ? b : a;
      if (!seen.add(List.of(host, tool, external))) continue;
      board.addFinding(
          new Finding(
              REMOTE_ACCESS_APP,
              "nDPI identified " + tool + " between " + host + " and " + external,
              Severity.MEDIUM,
              Grade.INFERRED,
              "ndpi",
              List.of(EntityRef.host(host), EntityRef.external(external)),
              List.of(c.id().toString()),
              Map.of("tool", tool)));
    }
  }
}
