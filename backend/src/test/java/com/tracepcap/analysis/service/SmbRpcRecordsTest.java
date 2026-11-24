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
