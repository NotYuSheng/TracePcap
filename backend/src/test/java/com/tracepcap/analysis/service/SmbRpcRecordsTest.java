package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Suricata's SMB and RPC records become grouped operations (#1266). The fixtures are the smb,
 * dcerpc and SMB fileinfo lines Suricata 8.0.8 (midstream on) logged for three PCAP-ATTACK captures
 * (github.com/sbousseaden/PCAP-ATTACK): PsExec, smbexec, and PsLoggedOn's enumeration.
 */
class SmbRpcRecordsTest {

  private static final String ATTACKER = "172.16.66.1";
  private static final String TARGET = "172.16.66.36";

  private final SuricataService suricata = new SuricataService(new SuricataEngine());

  @Test
  void psexec_copiesItsServiceToAdminShare_thenCreatesAndStartsIt() throws IOException {
    PcapParserService.ConversationInfo smb = conv(52445, 445);
    PcapParserService.ConversationInfo epm = conv(52446, 135);
    PcapParserService.ConversationInfo svcctl = conv(52447, 49688);
    suricata.apply(read("LM_psexec_smb_dcerpc_epm_svcctl"), List.of(smb, epm, svcctl));

    assertThat(smb.getRemoteOperations())
        .anySatisfy(o -> {
          assertThat(o.kind()).isEqualTo(SmbRpcRecords.SHARE);
          assertThat(o.share()).isEqualTo("\\\\172.16.66.36\\ADMIN$");
        })
        .anySatisfy(o -> {
          // The file is placed on the share its tree id was connected to.
          assertThat(o.kind()).isEqualTo(SmbRpcRecords.WRITE);
          assertThat(o.path()).isEqualTo("PSEXESVC.exe");
          assertThat(o.share()).isEqualTo("\\\\172.16.66.36\\ADMIN$");
          assertThat(o.bytes()).isEqualTo(145_568L);
        });
    // Suricata logged these calls with the server as the source (the stream began before the
    // capture did); the client is taken from the conversation.
    assertThat(svcctl.getRemoteOperations())
        .allSatisfy(o -> {
          assertThat(o.client()).isEqualTo(ATTACKER);
          assertThat(o.server()).isEqualTo(TARGET);
        })
        .extracting(SmbRpcRecords.Operation::opnum)
        .contains(15, 45, 19);
    assertThat(svcctl.getRemoteOperations())
        .filteredOn(o -> o.opnum() == 0)
        .singleElement()
        .satisfies(o -> assertThat(o.count()).isEqualTo(3)); // CloseServiceHandle, grouped
  }

  @Test
  void smbexec_createsAServiceAndReadsItsOutputBackFromCDrive() throws IOException {
    PcapParserService.ConversationInfo smb = conv(50060, 445);
    PcapParserService.ConversationInfo svcctl = conv(50059, 49683);
    suricata.apply(read("LM_smbexec_smb_dcerpc_svcctl_epm"), List.of(smb, svcctl));

    assertThat(svcctl.getRemoteOperations()).extracting(SmbRpcRecords.Operation::opnum).contains(27, 24, 31, 2);
    assertThat(smb.getRemoteOperations()).anySatisfy(o -> {
      assertThat(o.kind()).isEqualTo(SmbRpcRecords.READ);
      assertThat(o.path()).isEqualTo("__LegitFile");
      assertThat(o.share()).isEqualTo("\\\\172.16.66.36\\C$");
    });
  }

  @Test
  void rpcOverANamedPipe_keepsItsInterfaceAndOperation() throws IOException {
    PcapParserService.ConversationInfo smb = conv(51618, 445);
    suricata.apply(read("Discovery_PsLoggedOn_remotelocalusers_enum_winreg_lsarpc_dcerpc_smb"), List.of(smb));

    assertThat(smb.getRemoteOperations())
        .filteredOn(o -> SmbRpcRecords.RPC.equals(o.kind()))
        .extracting(SmbRpcRecords.Operation::interfaceUuid)
        .contains("12345778-1234-abcd-ef00-0123456789ab", "338cd001-2244-31f1-aaaa-900038001003");
    assertThat(smb.getRemoteOperations()).allSatisfy(o -> assertThat(o.client()).isEqualTo(ATTACKER));
  }

  @Test
  void aConversationOrientedFromTheSmbPort_isTurnedRound() {
    var ops = SmbRpcRecords.group(
        List.of(new SmbRpcRecords.Op(null, SmbRpcRecords.SHARE, "\\\\h\\IPC$", null, null, null, null, null)),
        TARGET, 445, ATTACKER, 50000);
    assertThat(ops).singleElement().satisfies(o -> {
      assertThat(o.client()).isEqualTo(ATTACKER);
      assertThat(o.server()).isEqualTo(TARGET);
    });
  }

  private static final String FAULTED =
      "{\"timestamp\":\"2020-07-19T21:14:41.000000+0800\",\"flow_id\":7,\"event_type\":\"dcerpc\","
          + "\"src_ip\":\"172.16.66.1\",\"src_port\":52447,\"dest_ip\":\"172.16.66.36\",\"dest_port\":49688,"
          + "\"proto\":\"TCP\",\"dcerpc\":{\"request\":\"REQUEST\",\"response\":\"FAULT\",\"req\":{\"opnum\":12},"
          + "\"interfaces\":[{\"uuid\":\"367abb81-9844-35f1-ad32-98f038001003\",\"ack_result\":0}]}}";

  @Test
  void aFaultedCall_carriesItsFault() {
    SuricataService.Eve eve = SuricataService.Eve.empty();
    suricata.parseEveLine(FAULTED, eve);
    PcapParserService.ConversationInfo c = conv(52447, 49688);
    suricata.apply(eve, List.of(c));
    assertThat(c.getRemoteOperations()).singleElement().satisfies(o -> assertThat(o.status()).isEqualTo("FAULT"));
  }

  @Test
  void aCallOnAConnectionThatAcceptedSeveralInterfaces_isSkipped_notGuessed() {
    String several = FAULTED.replace("\"response\":\"FAULT\"", "\"response\":\"RESPONSE\"")
        .replace("\"ack_result\":0}]", "\"ack_result\":0},{\"uuid\":\"9556dc99-828c-11cf-a37e-00aa003240c7\",\"ack_result\":0}]");
    SuricataService.Eve eve = SuricataService.Eve.empty();
    suricata.parseEveLine(several, eve);
    assertThat(eve.remoteOps()).isEmpty();
  }

  @Test
  void aFileOnATreeConnectedBeforeTheCapture_takesTheShareTheRecordNames() {
    String write = "{\"timestamp\":\"2020-07-19T21:14:41.000000+0800\",\"flow_id\":9,\"event_type\":\"fileinfo\","
        + "\"src_ip\":\"172.16.66.1\",\"src_port\":52445,\"dest_ip\":\"172.16.66.36\",\"dest_port\":445,"
        + "\"proto\":\"TCP\",\"app_proto\":\"smb\",\"smb\":{\"command\":\"SMB2_COMMAND_WRITE\",\"tree_id\":3,"
        + "\"share\":\"\\\\\\\\172.16.66.36\\\\ADMIN$\"},\"fileinfo\":{\"filename\":\"x.exe\",\"size\":10}}";
    SuricataService.Eve eve = SuricataService.Eve.empty();
    suricata.parseEveLine(write, eve);
    PcapParserService.ConversationInfo c = conv(52445, 445);
    suricata.apply(eve, List.of(c));
    assertThat(c.getRemoteOperations()).singleElement()
        .satisfies(o -> assertThat(o.share()).isEqualTo("\\\\172.16.66.36\\ADMIN$"));
  }

  @Test
  void twoConversationsOnOneFlowKey_shareItsOperationsOnce() {
    SuricataService.Eve eve = SuricataService.Eve.empty();
    suricata.parseEveLine(FAULTED, eve);
    PcapParserService.ConversationInfo a = conv(52447, 49688), b = conv(52447, 49688);
    suricata.apply(eve, List.of(a, b));
    assertThat(a.getRemoteOperations()).hasSize(1);
    assertThat(b.getRemoteOperations()).isEmpty();
  }

  @Test
  void theSideThatSentTheSyn_isTheClient() {
    var ops = SmbRpcRecords.group(
        List.of(new SmbRpcRecords.Op(null, SmbRpcRecords.RPC, null, null, "x", 1, null, null)),
        TARGET, 49688, ATTACKER, 52447, ATTACKER);
    assertThat(ops).singleElement().satisfies(o -> assertThat(o.client()).isEqualTo(ATTACKER));
  }

  private SuricataService.Eve read(String name) throws IOException {
    SuricataService.Eve eve = SuricataService.Eve.empty();
    try (InputStream in = getClass().getResourceAsStream("/suricata-smb/" + name + ".eve.json")) {
      assertThat(in).as(name).isNotNull();
      for (String line : new String(in.readAllBytes(), StandardCharsets.UTF_8).split("\n")) {
        suricata.parseEveLine(line, eve);
      }
    }
    return eve;
  }

  private static PcapParserService.ConversationInfo conv(int clientPort, int serverPort) {
    PcapParserService.ConversationInfo c = new PcapParserService.ConversationInfo();
    c.setSrcIp(ATTACKER);
    c.setSrcPort(clientPort);
    c.setDstIp(TARGET);
    c.setDstPort(serverPort);
    c.setTransport("TCP");
    c.setProtocol("TCP");
    c.setSuricataAlerts(new ArrayList<>());
    return c;
  }
}
