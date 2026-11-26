package com.tracepcap.knowledge.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracepcap.analysis.spi.ConversationLookup.HostPair;
import com.tracepcap.common.adjudication.ManualEvidenceEntity;
import com.tracepcap.knowledge.service.HoneypotRoleService.HostRole;
import com.tracepcap.knowledge.service.HoneypotRoleService.Signal;
import com.tracepcap.knowledge.service.HoneypotRoleService.Signature;
import java.util.ArrayList;
import java.util.List;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.tracepcap.analysis.spi.ConversationLookup;
import com.tracepcap.analysis.spi.ServiceBannerLookup;
import com.tracepcap.analysis.spi.ServiceBannerLookup.Banner;
import com.tracepcap.common.adjudication.HumanOverrideEntity;
import com.tracepcap.common.adjudication.HumanOverrideService;
import com.tracepcap.common.adjudication.ManualEvidenceRepository;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/** The honeypot role (docs/architecture/investigation-framework.rst, "Honeypots"). */
class HoneypotRoleServiceTest {

  private static final List<Signature> SIGNATURES =
      HoneypotRoleService.load(new ObjectMapper()).signatures();

  private static String[] seen(String kind, String value, int port) {
    return new String[] {kind, value, Integer.toString(port)};
  }

  /** {@code n} hosts each opening one conversation to {@code host}, which opens {@code out}. */
  private static List<HostPair> probed(String host, int n, int out) {
    List<HostPair> pairs = new ArrayList<>();
    for (int i = 1; i <= n; i++) pairs.add(new HostPair(host, "61.0.0." + i, 1, 0, 1));
    if (out > 0) pairs.add(new HostPair(host, "203.0.113.9", out, out, 0));
    return pairs;
  }

  private static HostRole role(String host, List<String[]> seen, List<HostPair> pairs, long ports,
      ManualEvidenceEntity... ev) {
    List<Signal> signals = new ArrayList<>(HoneypotRoleService.signatureSignals(seen, SIGNATURES));
    signals.addAll(HoneypotRoleService.behaviourSignals(host, pairs, ports, seen));
    return HoneypotRoleService.decide(host, signals, List.of(ev));
  }

  private static final List<String[]> COWRIE = List.of(
      seen("ssh-banner", "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3", 2222),
      seen("ssh-hassh", "6fa2f18e2061da02d6c8a9009674fa4e", 2222),
      seen("ttl", "64", 2222));

  private static final List<String[]> DIONAEA = List.of(
      seen("ftp-banner", "DiskStation FTP server ready.", 21),
      seen("smb-server-name", "HOMEUSER-3AF6FE", 445),
      seen("smb-os", "Windows 5.1 / Windows 2000 LAN Manager", 445),
      seen("mysql-version", "5.7.16", 3306),
      seen("http-server", "nginx", 80),
      seen("tls-cert", "subject C=GB, CN=Nepenthes Development Team, O=dionaea.carnivore.it, OU=anv;"
          + " issuer C=GB, CN=Nepenthes Development Team, O=dionaea.carnivore.it, OU=anv", 443),
      seen("ttl", "64", 445));

  private static ManualEvidenceEntity evidence(String label, int weight, String reason) {
    return ManualEvidenceEntity.builder().label(label).weight(weight).reason(reason).build();
  }

  @Test
  void theSignatureFileLoadsWithAStrengthAndAReasonForEach() {
    assertThat(SIGNATURES).isNotEmpty();
    assertThat(SIGNATURES).allSatisfy(s -> {
      assertThat(s.why()).isNotBlank();
      assertThat(s.honeypot()).isNotBlank();
      assertThat(s.match()).isIn("equals", "contains");
    });
  }

  @Test
  void stockDionaeaReadsAsDionaea() {
    HostRole r = role("198.51.100.45", DIONAEA, probed("198.51.100.45", 6, 0), 13);
    assertThat(r.label()).isEqualTo(HoneypotRoleService.HONEYPOT);
    assertThat(r.honeypot()).isEqualTo("Dionaea");
    assertThat(r.basis()).isEqualTo("MACHINE");
    assertThat(r.confidence()).isEqualTo(95);
    assertThat(r.described()).isEqualTo("198.51.100.45 is a Dionaea honeypot");
    assertThat(r.signals()).extracting(Signal::id).contains("dionaea-tls-cert",
        "dionaea-smb-server-name", "fan-in", "many-services", "os-mismatch");
    // Strongest first: the certificate and the SMB name lead.
    assertThat(r.signals().get(0).strength()).isEqualTo("STRONG");
  }

  @Test
  void stockCowrieReadsAsCowrieFromItsBannerHandshakeAndFanIn() {
    HostRole r = role("198.51.100.22", COWRIE, probed("198.51.100.22", 6, 0), 2);
    assertThat(r.isHoneypot()).isTrue();
    assertThat(r.honeypot()).isEqualTo("Cowrie");
    assertThat(r.signals()).extracting(Signal::id)
        .containsExactly("cowrie-ssh-hassh", "cowrie-ssh-banner", "fan-in");
  }

  @Test
  void aRealDebianServerWithCowriesBannerIsNotAHoneypot() {
    // The same banner, a real key exchange, and the fan-in any exposed server draws.
    HostRole r = role("203.0.113.5",
        List.<String[]>of(seen("ssh-banner", "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3", 22)),
        probed("203.0.113.5", 30, 0), 1);
    assertThat(r.label()).isNull();
    assertThat(r.honeypot()).isEqualTo("Cowrie");
    assertThat(r.reason()).contains("30 points of the 60");
  }

  @Test
  void oneSignalAloneIsNeverEnough() {
    HostRole r = role("10.0.0.5", List.<String[]>of(seen("ftp-banner", "DiskStation FTP server ready.", 21)),
        List.of(), 1);
    assertThat(r.label()).isNull();
    assertThat(r.reason()).contains("one signal only");
  }

  @Test
  void behaviourWithNoSignatureIsADecoysShapeNotAHoneypot() {
    // A high-interaction honeypot is a real system: nothing it sends is a honeypot's.
    HostRole r = role("10.0.2.15", List.<String[]>of(seen("ssh-banner", "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8", 22)),
        probed("10.0.2.15", 40, 0), 8);
    assertThat(r.label()).isNull();
    assertThat(r.reason()).contains("nothing it sent matches a honeypot");
  }

  @Test
  void aHostThatOpensItsOwnConnectionsDrawsNoFanInSignal() {
    assertThat(HoneypotRoleService.behaviourSignals("198.51.100.22", probed("198.51.100.22", 6, 40), 2,
        List.of())).isEmpty();
  }

  @Test
  void aWindowsTtlBehindWindowsSmbIsNoMismatch() {
    List<String[]> seen = List.<String[]>of(seen("smb-os", "Windows 5.1 / Windows 2000 LAN Manager", 445),
        seen("ttl", "128", 445));
    assertThat(HoneypotRoleService.behaviourSignals("10.0.0.7", List.of(), 1, seen)).isEmpty();
  }

  @Test
  void analystEvidenceCanSettleAHostTheSignalsLeaveOpen() {
    HostRole r = role("10.0.0.5", List.<String[]>of(seen("ftp-banner", "DiskStation FTP server ready.", 21)),
        List.of(), 1, evidence("Honeypot", 50, "our Dionaea sensor"));
    assertThat(r.isHoneypot()).isTrue();
    assertThat(r.basis()).isEqualTo("MACHINE");
    assertThat(r.signals()).extracting(Signal::source).containsExactly("signature", "analyst");
    assertThat(r.reason()).contains("analyst evidence: our Dionaea sensor");
  }

  @Test
  void evidenceAloneIsTheAnalystsAnswerNotAnInference() {
    HostRole r = role("10.0.0.5", List.of(), List.of(), 0,
        evidence("Honeypot", 40, "T-Pot box"), evidence("Honeypot", 30, "in the asset list"));
    assertThat(r.isHoneypot()).isTrue();
    assertThat(r.basis()).isEqualTo("HUMAN");
  }

  @Test
  void oneStrongPieceOfEvidenceSettlesAHostAlone() {
    HostRole r = role("10.0.0.5", List.of(), List.of(), 0, evidence("Honeypot", 80, "our T-Pot"));
    assertThat(r.isHoneypot()).isTrue();
    assertThat(r.basis()).isEqualTo("HUMAN");
    HostRole weak = role("10.0.0.5", List.of(), List.of(), 0, evidence("Honeypot", 40, "maybe"));
    assertThat(weak.label()).isNull();
    assertThat(weak.reason()).isEqualTo("only analyst evidence, worth 40 points of the 60 it needs");
  }

  @Test
  void anAnalystsWordsForNoMeanNotAHoneypotWhereverTheyAreTyped() {
    HostRole inferred = role("198.51.100.22", COWRIE, probed("198.51.100.22", 6, 0), 2);
    assertThat(HoneypotRoleService.overridden(inferred, "not", null, "ana").isHoneypot()).isFalse();
    assertThat(HoneypotRoleService.overridden(inferred, "Not a honeypot", null, "ana").label())
        .isEqualTo(HoneypotRoleService.NOT_HONEYPOT);
    assertThat(role("10.0.0.5", List.of(), List.of(), 0, evidence("no", 50, "ours")).label())
        .isEqualTo(HoneypotRoleService.NOT_HONEYPOT);
    // A label of their own names what it is.
    assertThat(HoneypotRoleService.overridden(inferred, "T-Pot sensor", null, "ana").isHoneypot()).isTrue();
  }

  @Test
  void evidenceAgainstOutweighingTheSignalsSaysNotAHoneypot() {
    HostRole r = role("198.51.100.22", COWRIE, probed("198.51.100.22", 6, 0), 2,
        evidence("Not a honeypot", 90, "our own bastion, on a Twisted SSH server"));
    assertThat(r.label()).isEqualTo(HoneypotRoleService.NOT_HONEYPOT);
    assertThat(r.isHoneypot()).isFalse();
    assertThat(r.candidates()).extracting(HoneypotRoleService.Candidate::label)
        .containsExactly(HoneypotRoleService.NOT_HONEYPOT, HoneypotRoleService.HONEYPOT);
  }

  @Test
  void anOverrideWinsOutrightAndKeepsTheSignals() {
    HostRole inferred = role("198.51.100.22", COWRIE, probed("198.51.100.22", 6, 0), 2);
    HostRole r = HoneypotRoleService.overridden(inferred, "not a honeypot", "it's our bastion", "ana");
    assertThat(r.label()).isEqualTo(HoneypotRoleService.NOT_HONEYPOT);
    assertThat(r.honeypot()).isNull();
    assertThat(r.basis()).isEqualTo("HUMAN");
    assertThat(r.overriddenBy()).isEqualTo("ana");
    assertThat(r.signals()).isEqualTo(inferred.signals());
    assertThat(r.described()).isEqualTo("198.51.100.22 is not a honeypot");
  }

  @Test
  void aTlsSignatureMatchesTheSubjectOrIssuer() {
    List<Signal> s = HoneypotRoleService.signatureSignals(
        List.<String[]>of(seen("tls-cert", "subject CN=x; issuer O=dionaea.carnivore.it", 443)), SIGNATURES);
    assertThat(s).extracting(Signal::id).containsExactly("dionaea-tls-cert");
    assertThat(s.get(0).text()).contains("on port 443");
  }

  // ── A whole capture ────────────────────────────────────────────────────────────────────────

  private static final UUID FILE = UUID.randomUUID();

  private static HoneypotRoleService service(List<Banner> banners, List<HostPair> pairs,
      HumanOverrideEntity override, ManualEvidenceEntity... ev) {
    ServiceBannerLookup b = mock(ServiceBannerLookup.class);
    when(b.banners(FILE)).thenReturn(banners);
    ConversationLookup c = mock(ConversationLookup.class);
    when(c.hostPairs(FILE)).thenReturn(pairs);
    when(c.tlsConversations(FILE)).thenReturn(List.of());
    when(c.distinctAnsweredPorts(eq(FILE), anyString())).thenReturn(1L);
    HumanOverrideService o = mock(HumanOverrideService.class);
    when(o.findAll(HoneypotRoleService.QUESTION, FILE))
        .thenReturn(override == null ? List.of() : List.of(override));
    ManualEvidenceRepository e = mock(ManualEvidenceRepository.class);
    when(e.findByQuestionAndFileId(any(), any())).thenReturn(List.of(ev));
    return new HoneypotRoleService(b, c, o, e, new ObjectMapper());
  }

  private static List<Banner> cowrie(String ip) {
    return List.of(new Banner(ip, 2222, "ssh-banner", "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3", 6),
        new Banner(ip, 2222, "ssh-hassh", "6fa2f18e2061da02d6c8a9009674fa4e", 6));
  }

  @Test
  void aCaptureNamesItsHoneypotsAndCountsTheHostsWithOnlyAStockBanner() {
    List<Banner> banners = new ArrayList<>(cowrie("198.51.100.22"));
    // Servers a scan reached that still send an old Cowrie default, and nothing else.
    for (int i = 1; i <= 3; i++) {
      banners.add(new Banner("203.0.113." + i, 22, "ssh-banner", "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2", 1));
    }
    banners.add(new Banner("192.0.2.80", 80, "http-server", "nginx", 4));
    var r = service(banners, probed("198.51.100.22", 6, 0), null).forFile(FILE);
    assertThat(r.hosts()).extracting(HostRole::host).containsExactly("198.51.100.22");
    assertThat(r.honeypots()).hasSize(1);
    assertThat(r.singleSignal()).isEqualTo(3);
    assertThat(r.serversChecked()).isEqualTo(5);
    assertThat(r.signaturesVersion()).isNotBlank();
  }

  @Test
  void anOverriddenHostIsListedEvenWithOneSignal() {
    HumanOverrideEntity o = mock(HumanOverrideEntity.class);
    when(o.getEntityKey()).thenReturn("203.0.113.1");
    when(o.getLabel()).thenReturn("Honeypot");
    when(o.getActor()).thenReturn("ana");
    var r = service(List.of(new Banner("203.0.113.1", 22, "ssh-banner",
        "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2", 1)), List.of(), o).forFile(FILE);
    assertThat(r.hosts()).extracting(HostRole::basis).containsExactly("HUMAN");
    assertThat(r.singleSignal()).isZero();
  }

  @Test
  void evidenceOnAHostWithNoSignalBringsItIntoTheReport() {
    ManualEvidenceEntity ev = ManualEvidenceEntity.builder().label("Honeypot").weight(40)
        .reason("T-Pot").entityKey("10.0.0.5").build();
    var r = service(List.of(), List.of(), null, ev).forFile(FILE);
    assertThat(r.hosts()).extracting(HostRole::host).containsExactly("10.0.0.5");
  }

  @Test
  void anOverrideOnAHostWithNoSignalStillAnswersIt() {
    HumanOverrideEntity o = mock(HumanOverrideEntity.class);
    when(o.getEntityKey()).thenReturn("10.0.2.15");
    when(o.getLabel()).thenReturn("Honeypot");
    var r = service(List.of(), List.of(), o).forFile(FILE);
    assertThat(r.honeypots()).extracting(HostRole::host).containsExactly("10.0.2.15");
  }

  @Test
  void serversThatSentOnlyASynAckAreNotCountedAsChecked() {
    var r = service(List.of(new Banner("192.0.2.1", 443, "ttl", "64", 1),
        new Banner("192.0.2.80", 80, "http-server", "nginx", 4)), List.of(), null).forFile(FILE);
    assertThat(r.serversChecked()).isEqualTo(1);
  }

  @Test
  void aCaptureWithNoMatchHasNoHosts() {
    var r = service(List.of(new Banner("192.0.2.80", 80, "http-server", "nginx", 4)), List.of(), null)
        .forFile(FILE);
    assertThat(r.hosts()).isEmpty();
    assertThat(r.serversChecked()).isEqualTo(1);
  }
}
