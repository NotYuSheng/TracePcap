package com.tracepcap.knowledge.contributor;

import com.tracepcap.analysis.spi.ConversationLookup.ConversationFacts;
import com.tracepcap.analysis.spi.RemoteOperationLookup;
import com.tracepcap.analysis.spi.RemoteOperationLookup.RemoteOperationFacts;
import com.tracepcap.common.net.MsRpc;
import com.tracepcap.knowledge.spi.CaseKnowledgeBuilder;
import com.tracepcap.knowledge.spi.EntityRef;
import com.tracepcap.knowledge.spi.Finding;
import com.tracepcap.knowledge.spi.Grade;
import com.tracepcap.knowledge.spi.KnowledgeContext;
import com.tracepcap.knowledge.spi.KnowledgeContributor;
import com.tracepcap.knowledge.spi.Severity;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Component;

/**
 * One host making another run something (#1266), from the SMB and RPC operations Suricata logged:
 * a service created on it (PsExec, smbexec, Impacket), a scheduled task registered, a WMI method
 * called, an executable copied to an admin share, or a directory replication asked of a domain
 * controller by a host that isn't one (DCSync).
 *
 * <p>Deliberately not: connecting to IPC$, reading SYSVOL or NETLOGON (every domain member does it
 * at logon to read group policy), share and user enumeration (srvsvc, samr, lsarpc), remote registry
 * and the endpoint mapper. They are routine in a domain, and posting them would bury the operations
 * that let one machine act on another.
 *
 * <p>One finding per client, server and technique, MEASURED: the request was in the traffic. What
 * it means (an attacker, or an administrator's tool) is for the analyst to decide.
 */
@Component
public class LateralMovementContributor implements KnowledgeContributor {

  public static final String LATERAL_MOVEMENT = "lateral-movement";

  public static final String REMOTE_SERVICE = "remote-service";
  public static final String SCHEDULED_TASK = "scheduled-task";
  public static final String WMI_EXEC = "wmi-exec";
  public static final String ADMIN_SHARE_COPY = "admin-share-copy";
  public static final String DCSYNC = "dcsync";

  /** svcctl operations that make a service run a new command: create one, or repoint one. */
  private static final Set<Integer> SERVICE_CHANGES = Set.of(11, 12, 23, 24, 44, 45);
  private static final Set<Integer> SERVICE_STARTS = Set.of(19, 31);

  /** An admin share: ADMIN$ or a drive's (C$, D$…). IPC$ is not one. */
  private static final Pattern ADMIN_SHARE = Pattern.compile("(?i).*\\\\(ADMIN|[A-Z])\\$$");

  /** A file that runs: what a tool copies before running it. */
  private static final Pattern RUNNABLE =
      Pattern.compile("(?i).*\\.(exe|dll|sys|bat|cmd|ps1|vbs|js|hta|scr|msi|com)$");

  /** Ports a domain controller answers on: Kerberos, LDAP, global catalog. */
  private static final Set<Integer> DC_PORTS = Set.of(88, 389, 636, 3268, 3269);

  private final ObjectProvider<RemoteOperationLookup> operations;

  public LateralMovementContributor(ObjectProvider<RemoteOperationLookup> operations) {
    this.operations = operations;
  }

  @Override
  public String name() {
    return "lateral-movement";
  }

  @Override
  public void contribute(KnowledgeContext context, CaseKnowledgeBuilder board) {
    RemoteOperationLookup lookup = operations.getIfAvailable();
    if (lookup == null) return;
    List<RemoteOperationFacts> ops = lookup.forFile(context.fileId());
    if (ops.isEmpty()) return;
    post(ops, domainControllers(context.conversationFacts(), ops), board);
  }

  /**
   * Hosts acting as domain controllers in this capture, between which replication is normal: those
   * answering Kerberos or LDAP, and those answering directory replication (a short capture of the
   * replication link may hold none of a DC's Kerberos or LDAP).
   */
  static Set<String> domainControllers(List<ConversationFacts> conversations, List<RemoteOperationFacts> ops) {
    Set<String> dcs = new HashSet<>();
    for (ConversationFacts c : conversations) {
      if (c.flow() == null || c.flow().dstIp() == null || c.flow().dstPort() == null) continue;
      if (DC_PORTS.contains(c.flow().dstPort())) dcs.add(c.flow().dstIp());
    }
    for (RemoteOperationFacts o : ops) {
      if ("rpc".equals(o.kind()) && MsRpc.DRSUAPI.equals(o.interfaceUuid()) && o.server() != null) {
        dcs.add(o.server());
      }
    }
    return dcs;
  }

  /** The board-facing part, unit-testable without a lookup. */
  static void post(List<RemoteOperationFacts> ops, Set<String> domainControllers, CaseKnowledgeBuilder board) {
    // (client, server) -> technique -> what showed it
    Map<List<String>, Map<String, Evidence>> pairs = new LinkedHashMap<>();
    for (RemoteOperationFacts o : ops) {
      if (o.client() == null || o.server() == null || o.client().equals(o.server())) continue;
      String technique = technique(o, domainControllers);
      if (technique == null) continue;
      pairs.computeIfAbsent(List.of(o.client(), o.server()), k -> new LinkedHashMap<>())
          .computeIfAbsent(technique, k -> new Evidence())
          .add(o, describe(o));
    }
    // What else the same client did on the same server, shown beside a technique: the service it
    // started, the admin share it connected to, the files it read back.
    for (RemoteOperationFacts o : ops) {
      Map<String, Evidence> found = pairs.get(List.of(String.valueOf(o.client()), String.valueOf(o.server())));
      if (found == null || technique(o, domainControllers) != null) continue;
      String also = supporting(o);
      if (also == null) continue;
      found.values().forEach(e -> e.support(o, also));
    }
    pairs.forEach((pair, techniques) -> techniques.forEach((technique, e) -> {
      Map<String, Object> attrs = new LinkedHashMap<>();
      attrs.put("technique", technique);
      attrs.put("client", pair.get(0));
      attrs.put("server", pair.get(1));
      attrs.put("operations", List.copyOf(e.lines));
      if (e.first != null) attrs.put("firstSeen", TrafficContributor.utc(e.first));
      board.addFinding(new Finding(
          LATERAL_MOVEMENT,
          pair.get(0) + " → " + pair.get(1) + ": " + String.join("; ", e.lines),
          technique.equals(DCSYNC) || technique.equals(REMOTE_SERVICE) ? Severity.HIGH : Severity.MEDIUM,
          Grade.MEASURED,
          "suricata",
          List.of(EntityRef.host(pair.get(0)), EntityRef.host(pair.get(1))),
          e.conversations.stream().map(UUID::toString).toList(),
          attrs));
    }));
  }

  /** The technique this one operation shows on its own, or null. */
  static String technique(RemoteOperationFacts o, Set<String> domainControllers) {
    if (o.status() != null) return null; // refused: an attempt, not an action
    if ("rpc".equals(o.kind()) && o.interfaceUuid() != null && o.opnum() != null) {
      String uuid = o.interfaceUuid().toLowerCase(Locale.ROOT);
      int op = o.opnum();
      if (uuid.equals(MsRpc.SVCCTL) && SERVICE_CHANGES.contains(op)) return REMOTE_SERVICE;
      if ((uuid.equals(MsRpc.ATSVC) && op == 0) || (uuid.equals(MsRpc.TASK_SCHEDULER) && op == 1)) {
        return SCHEDULED_TASK;
      }
      if (uuid.equals(MsRpc.WBEM_SERVICES) && (op == 24 || op == 25)) return WMI_EXEC;
      if (uuid.equals(MsRpc.DRSUAPI) && op == 3 && !domainControllers.contains(o.client())) return DCSYNC;
      return null;
    }
    if ("write".equals(o.kind()) && adminShare(o.share()) && o.path() != null
        && RUNNABLE.matcher(o.path()).matches()) {
      return ADMIN_SHARE_COPY;
    }
    return null;
  }

  private static boolean adminShare(String share) {
    return share != null && ADMIN_SHARE.matcher(share).matches();
  }

  /** "CreateServiceW", "wrote PSEXESVC.exe (145,568 bytes) to \\host\ADMIN$". */
  static String describe(RemoteOperationFacts o) {
    if ("rpc".equals(o.kind())) {
      String name = o.operation() != null ? o.operation() : "operation " + o.opnum();
      String iface = o.interfaceName() != null ? o.interfaceName() : o.interfaceUuid();
      return iface + " " + name + (o.count() > 1 ? " (" + o.count() + "×)" : "");
    }
    return switch (o.kind()) {
      case "write" -> "wrote " + o.path() + bytes(o.bytes()) + (o.share() != null ? " to " + o.share() : "");
      case "read" -> "read " + o.path() + bytes(o.bytes()) + (o.share() != null ? " from " + o.share() : "");
      case "share" -> "connected to " + o.share();
      default -> "opened " + o.path() + (o.share() != null ? " on " + o.share() : "");
    };
  }

  /** An operation worth listing beside a technique on the same pair, or null. */
  private static String supporting(RemoteOperationFacts o) {
    if (o.status() != null) return null;
    if ("rpc".equals(o.kind()) && MsRpc.SVCCTL.equals(o.interfaceUuid()) && SERVICE_STARTS.contains(o.opnum())) {
      return describe(o);
    }
    if ("share".equals(o.kind()) && adminShare(o.share())) return describe(o);
    if (("write".equals(o.kind()) || "read".equals(o.kind())) && adminShare(o.share())) return describe(o);
    return null;
  }

  private static String bytes(Long n) {
    return n == null ? "" : " (" + String.format(Locale.ROOT, "%,d", n) + " bytes)";
  }

  /** What showed one technique on one pair. */
  private static final class Evidence {
    final Set<String> lines = new LinkedHashSet<>();
    final Set<UUID> conversations = new LinkedHashSet<>();
    LocalDateTime first;

    void add(RemoteOperationFacts o, String line) {
      lines.add(line);
      if (o.conversationId() != null) conversations.add(o.conversationId());
      if (o.firstTime() != null && (first == null || o.firstTime().isBefore(first))) first = o.firstTime();
    }

    void support(RemoteOperationFacts o, String line) {
      lines.add(line);
      if (o.conversationId() != null) conversations.add(o.conversationId());
    }
  }

}
