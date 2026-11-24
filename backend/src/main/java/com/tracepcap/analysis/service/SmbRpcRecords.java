package com.tracepcap.analysis.service;

import com.fasterxml.jackson.databind.JsonNode;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Reads Suricata's {@code smb}, {@code dcerpc} and SMB {@code fileinfo} records (#1266): the shares a
 * host connected to, the files and pipes it opened, the files it copied, and the RPC calls it made.
 * This is the evidence of one Windows host acting on another (a service installed, a task
 * scheduled, a directory replicated), which no other part of the analysis sees.
 *
 * <p>Only what someone would look at is kept: negotiation, session setup, closes, ioctls without an
 * RPC call and other housekeeping are dropped, and identical operations on one conversation become
 * one row with a count (a Zerologon attempt is hundreds of identical calls).
 *
 * <p>Suricata's {@code src_ip} on these records is the side of the flow it saw first, which for a
 * connection already open when the capture began can be the server. Which side is the client is
 * therefore taken from the conversation, not from the record.
 */
final class SmbRpcRecords {

  private SmbRpcRecords() {}

  /** At most this many operations are kept per capture, before grouping. */
  static final int MAX_OPERATIONS = 20_000;

  static final String SHARE = "share";
  static final String OPEN = "open";
  static final String WRITE = "write";
  static final String READ = "read";
  static final String RPC = "rpc";

  /** One operation as Suricata logged it. {@code share} is "\\host\ADMIN$" as connected. */
  record Op(
      LocalDateTime time, String kind, String share, String path, String interfaceUuid,
      Integer opnum, Long bytes, String status) {}

  /**
   * One kind of operation on a conversation (#1266), grouped: who did it to whom, how often, and
   * when it first happened.
   */
  public record Operation(
      LocalDateTime firstTime, String client, String server, String kind, String share, String path,
      String interfaceUuid, Integer opnum, Long bytes, String status, int count) {}

  /** Whether this line may be one of the records read here; cheap, before parsing. */
  static boolean mayBe(String line) {
    return line.contains("\"event_type\":\"smb\"") || line.contains("\"event_type\":\"dcerpc\"")
        || (line.contains("\"event_type\":\"fileinfo\"") && line.contains("\"app_proto\":\"smb\""));
  }

  /**
   * Reads one record into {@code ops}, keyed by flow. {@code trees} remembers which share each SMB
   * tree id was, per flow, so a file opened later can be placed on ADMIN$ or C$.
   */
  static void read(
      JsonNode root, String type, String flowKey, Map<String, List<Op>> ops,
      java.util.concurrent.atomic.AtomicInteger count, Map<String, String> trees) {
    // A running count: summing every flow's list on each line is quadratic on a busy capture.
    if (count.get() >= MAX_OPERATIONS) return;
    LocalDateTime time = SuricataService.eveTime(root.path("timestamp").asText(null));
    String flowId = root.path("flow_id").asText("");
    List<Op> out = new ArrayList<>(2);
    switch (type) {
      case "dcerpc" -> rpc(root.path("dcerpc"), time, null, out);
      case "smb" -> smb(root.path("smb"), time, flowId, trees, out);
      case "fileinfo" -> file(root, time, flowId, trees, out);
      default -> { }
    }
    if (!out.isEmpty()) {
      ops.computeIfAbsent(flowKey, k -> new ArrayList<>()).addAll(out);
      count.addAndGet(out.size());
    }
  }

  private static void smb(
      JsonNode smb, LocalDateTime time, String flowId, Map<String, String> trees, List<Op> out) {
    String command = smb.path("command").asText("");
    String status = status(smb);
    String tree = flowId + "/" + smb.path("tree_id").asText("");
    if (command.contains("TREE_CONNECT")) {
      String share = text(smb, "share");
      if (share == null) share = text(smb, "named_pipe");
      if (share == null) return;
      if (status == null) trees.put(tree, share);
      out.add(new Op(time, SHARE, share, null, null, null, null, status));
      return;
    }
    if (command.endsWith("CREATE") || command.contains("NT_CREATE")) {
      String name = text(smb, "filename");
      if (name != null) out.add(new Op(time, OPEN, trees.get(tree), name, null, null, null, status));
      return;
    }
    // An RPC call carried over a named pipe (srvsvc, samr, lsarpc… over IPC$).
    JsonNode rpc = smb.path("dcerpc");
    if (!rpc.isMissingNode() && !rpc.isNull()) rpc(rpc, time, trees.get(tree), out);
  }

  /** A DCE-RPC request, over TCP or over a named pipe; binds and unknown interfaces are skipped. */
  private static void rpc(JsonNode rpc, LocalDateTime time, String share, List<Op> out) {
    if (!"REQUEST".equals(rpc.path("request").asText(""))) return;
    Integer opnum = rpc.has("opnum") ? Integer.valueOf(rpc.get("opnum").asInt())
        : rpc.path("req").has("opnum") ? Integer.valueOf(rpc.path("req").get("opnum").asInt()) : null;
    String uuid = null;
    for (JsonNode i : rpc.path("interfaces")) {
      // The accepted one when the bind offered several (ack_result 0), else the first.
      if (uuid == null || i.path("ack_result").asInt(-1) == 0) uuid = text(i, "uuid");
      if (i.path("ack_result").asInt(-1) == 0) break;
    }
    // Without its bind (it happened before the capture began) the interface is unknown, and an
    // operation number alone means nothing.
    if (uuid == null || opnum == null) return;
    out.add(new Op(time, RPC, share, null, uuid.toLowerCase(Locale.ROOT), opnum, null, null));
  }

  /** A file Suricata saw cross an SMB session: written to the server, or read from it. */
  private static void file(
      JsonNode root, LocalDateTime time, String flowId, Map<String, String> trees, List<Op> out) {
    JsonNode smb = root.path("smb"), info = root.path("fileinfo");
    String name = text(info, "filename");
    if (name == null) return;
    String command = smb.path("command").asText("");
    String kind = command.contains("WRITE") ? WRITE : command.contains("READ") ? READ : null;
    if (kind == null) return;
    String share = trees.get(flowId + "/" + smb.path("tree_id").asText(""));
    Long size = info.has("size") ? info.get("size").asLong() : null;
    out.add(new Op(time, kind, share, name, null, null, size, null));
  }

  /** Null when it succeeded or Suricata didn't say. */
  private static String status(JsonNode smb) {
    String s = text(smb, "status");
    return s == null || "STATUS_SUCCESS".equals(s) || "STATUS_MORE_PROCESSING_REQUIRED".equals(s)
        ? null : s.length() > 64 ? s.substring(0, 64) : s;
  }

  private static String text(JsonNode n, String field) {
    JsonNode v = n.path(field);
    if (v.isMissingNode() || v.isNull()) return null;
    String s = v.asText("").trim();
    if (s.isEmpty()) return null;
    return s.length() > 1024 ? s.substring(0, 1024) : s;
  }

  /** Ports a file-sharing server listens on; the other side of the conversation is the client. */
  private static final Set<Integer> SMB_PORTS = Set.of(445, 139);

  /**
   * Groups a conversation's operations. The client is the conversation's source unless that side
   * is on the SMB port, which only a server is.
   */
  static List<Operation> group(
      List<Op> ops, String srcIp, Integer srcPort, String dstIp, Integer dstPort) {
    boolean swap = srcPort != null && SMB_PORTS.contains(srcPort)
        && (dstPort == null || !SMB_PORTS.contains(dstPort));
    String client = swap ? dstIp : srcIp, server = swap ? srcIp : dstIp;
    Map<List<Object>, Operation> grouped = new LinkedHashMap<>();
    for (Op o : ops) {
      List<Object> key = java.util.Arrays.asList(
          o.kind(), o.share(), o.path(), o.interfaceUuid(), o.opnum(), o.status());
      Operation prev = grouped.get(key);
      if (prev == null) {
        grouped.put(key, new Operation(o.time(), client, server, o.kind(), o.share(), o.path(),
            o.interfaceUuid(), o.opnum(), o.bytes(), o.status(), 1));
      } else {
        LocalDateTime first = prev.firstTime() == null || (o.time() != null && o.time().isBefore(prev.firstTime()))
            ? o.time() : prev.firstTime();
        Long bytes = prev.bytes() == null ? o.bytes()
            : o.bytes() == null ? prev.bytes() : Long.valueOf(prev.bytes() + o.bytes());
        grouped.put(key, new Operation(first, client, server, o.kind(), o.share(), o.path(),
            o.interfaceUuid(), o.opnum(), bytes, o.status(), prev.count() + 1));
      }
    }
    return new ArrayList<>(grouped.values());
  }
}
