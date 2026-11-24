package com.tracepcap.knowledge.contributor;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.analysis.spi.RemoteOperationLookup.RemoteOperationFacts;
import com.tracepcap.common.net.MsRpc;
import com.tracepcap.knowledge.spi.Answer;
import com.tracepcap.knowledge.spi.CaseKnowledge;
import com.tracepcap.knowledge.spi.CaseKnowledgeBuilder;
import com.tracepcap.knowledge.spi.Finding;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Lateral movement from SMB and RPC operations (#1266): the operations that make another host run
 * something are posted, and a domain's routine traffic isn't. Operations as PCAP-ATTACK's PsExec,
 * smbexec and PsLoggedOn captures produce them (see SmbRpcRecordsTest).
 */
class LateralMovementContributorTest {

  private static final String A = "172.16.66.1", T = "172.16.66.36", DC = "10.0.0.10", WS = "10.0.0.50";
  private static final UUID CONV = UUID.randomUUID();
  private static final LocalDateTime AT = LocalDateTime.of(2020, 7, 19, 21, 14, 41);

  @Test
  void psexec_isARemoteServiceAndAnAdminShareCopy() {
    CaseKnowledge board = board(List.of(
        share(A, T, "\\\\172.16.66.36\\ADMIN$"),
        file("write", A, T, "\\\\172.16.66.36\\ADMIN$", "PSEXESVC.exe", 145_568L),
        rpc(A, T, MsRpc.SVCCTL, 15),
        rpc(A, T, MsRpc.SVCCTL, 45),
        rpc(A, T, MsRpc.SVCCTL, 19)), Set.of());

    assertThat(board.findingsOfCategory(LateralMovementContributor.LATERAL_MOVEMENT))
        .extracting(f -> f.attributes().get("technique"))
        .containsExactlyInAnyOrder(LateralMovementContributor.REMOTE_SERVICE, LateralMovementContributor.ADMIN_SHARE_COPY);
    Finding service = byTechnique(board, LateralMovementContributor.REMOTE_SERVICE);
    assertThat((List<?>) service.attributes().get("operations")).map(String::valueOf).contains(
        "svcctl CreateServiceWOW64W", "svcctl StartServiceW", "connected to \\\\172.16.66.36\\ADMIN$");
    assertThat(service.evidence()).containsExactly(CONV.toString());

    List<Answer> answers = new com.tracepcap.knowledge.question.LateralMovementQuestion().answer(board);
    assertThat(answers).singleElement().satisfies(a -> {
      assertThat(a.attributes()).containsEntry("client", A).containsEntry("server", T);
      assertThat(a.basis()).contains("svcctl CreateServiceWOW64W", "wrote PSEXESVC.exe (145,568 bytes) to \\\\172.16.66.36\\ADMIN$");
      assertThat(a.headline()).isEqualTo(A + " created a service on " + T + " over RPC and copied a"
          + " program to an admin share on " + T + " (from "
          + TrafficContributor.readable(TrafficContributor.utc(AT)) + ")."
          + " That is how PsExec and smbexec run a command on another machine."
          + " Confirm an administrator did this.");
    });
  }

  @Test
  void smbexec_isARemoteServiceWithTheOutputItReadBack() {
    CaseKnowledge board = board(List.of(
        rpc(A, T, MsRpc.SVCCTL, 27), rpc(A, T, MsRpc.SVCCTL, 24), rpc(A, T, MsRpc.SVCCTL, 31),
        file("read", A, T, "\\\\172.16.66.36\\C$", "__LegitFile", 93L)), Set.of());

    Finding f = byTechnique(board, LateralMovementContributor.REMOTE_SERVICE);
    assertThat((List<?>) f.attributes().get("operations")).map(String::valueOf)
        .contains("svcctl CreateServiceA", "svcctl StartServiceA", "read __LegitFile (93 bytes) from \\\\172.16.66.36\\C$");
  }

  @Test
  void routineDomainTraffic_postsNothing() {
    // A member's logon: IPC$, SYSVOL and its group-policy files, NETLOGON, the endpoint mapper,
    // share, user and SID lookups, remote registry. And a C$ read that isn't a program.
    CaseKnowledge board = board(List.of(
        share(WS, DC, "\\\\dc\\IPC$"),
        share(WS, DC, "\\\\dc\\SYSVOL"),
        file("read", WS, DC, "\\\\dc\\SYSVOL", "corp.local\\Policies\\{31B2F340}\\GPT.INI", 22L),
        file("write", WS, DC, "\\\\dc\\Shared_Files", "report.exe", 1000L),
        share(WS, DC, "\\\\dc\\NETLOGON"),
        rpc(WS, DC, "e1af8308-5d1f-11c9-91a4-08002b14a0fa", 3),
        rpc(WS, DC, "4b324fc8-1670-01d3-1278-5a47bf6ee188", 15),
        rpc(WS, DC, "12345778-1234-abcd-ef00-0123456789ac", 17),
        rpc(WS, DC, "12345778-1234-abcd-ef00-0123456789ab", 76),
        rpc(WS, DC, "338cd001-2244-31f1-aaaa-900038001003", 6),
        file("write", WS, DC, "\\\\dc\\C$", "notes.txt", 10L)), Set.of(DC));

    assertThat(board.findingsOfCategory(LateralMovementContributor.LATERAL_MOVEMENT)).isEmpty();
  }

  @Test
  void replication_isDcsyncOnlyFromAHostThatIsntADomainController() {
    List<RemoteOperationFacts> ops = List.of(rpc(A, DC, MsRpc.DRSUAPI, 3));
    assertThat(board(ops, Set.of(DC)).findingsOfCategory(LateralMovementContributor.LATERAL_MOVEMENT))
        .singleElement()
        .satisfies(f -> assertThat(f.attributes()).containsEntry("technique", LateralMovementContributor.DCSYNC));
    // Between two domain controllers it's how the directory stays in sync.
    List<RemoteOperationFacts> dcToDc = List.of(rpc("10.0.0.11", DC, MsRpc.DRSUAPI, 3));
    assertThat(board(dcToDc, Set.of(DC, "10.0.0.11")).findingsOfCategory(LateralMovementContributor.LATERAL_MOVEMENT)).isEmpty();
  }

  @Test
  void aRefusedCall_isAnAttemptNotAnAction() {
    RemoteOperationFacts denied = new RemoteOperationFacts(CONV, AT, A, T, "write", "\\\\h\\ADMIN$", "x.exe",
        null, null, null, null, 10L, "STATUS_ACCESS_DENIED", 1);
    assertThat(board(List.of(denied), Set.of()).findingsOfCategory(LateralMovementContributor.LATERAL_MOVEMENT)).isEmpty();
  }

  @Test
  void scheduledTaskAndWmi_arePosted() {
    CaseKnowledge board = board(List.of(
        rpc(A, T, MsRpc.TASK_SCHEDULER, 1), rpc(A, "172.16.66.37", MsRpc.WBEM_SERVICES, 24)), Set.of());
    assertThat(board.findingsOfCategory(LateralMovementContributor.LATERAL_MOVEMENT))
        .extracting(f -> f.attributes().get("technique"))
        .containsExactly(LateralMovementContributor.SCHEDULED_TASK, LateralMovementContributor.WMI_EXEC);
  }

  private static CaseKnowledge board(List<RemoteOperationFacts> ops, Set<String> dcs) {
    CaseKnowledgeBuilder b = new CaseKnowledgeBuilder(UUID.randomUUID());
    LateralMovementContributor.post(ops, dcs, b);
    return b.build();
  }

  private static Finding byTechnique(CaseKnowledge board, String technique) {
    return board.findingsOfCategory(LateralMovementContributor.LATERAL_MOVEMENT).stream()
        .filter(f -> technique.equals(f.attributes().get("technique"))).findFirst().orElseThrow();
  }

  private static RemoteOperationFacts rpc(String client, String server, String uuid, int opnum) {
    return new RemoteOperationFacts(CONV, AT, client, server, "rpc", null, null, uuid,
        MsRpc.interfaceName(uuid), opnum, MsRpc.operationName(uuid, opnum), null, null, 1);
  }

  private static RemoteOperationFacts share(String client, String server, String share) {
    return new RemoteOperationFacts(CONV, AT, client, server, "share", share, null, null, null, null, null, null, null, 1);
  }

  private static RemoteOperationFacts file(String kind, String client, String server, String share, String path, Long bytes) {
    return new RemoteOperationFacts(CONV, AT, client, server, kind, share, path, null, null, null, null, bytes, null, 1);
  }
}
