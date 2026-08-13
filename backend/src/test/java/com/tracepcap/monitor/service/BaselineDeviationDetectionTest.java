package com.tracepcap.monitor.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.tracepcap.analysis.spi.ConversationLookup;
import com.tracepcap.analysis.spi.GeoOrgLookup;
import com.tracepcap.analysis.spi.HostClassificationLookup;
import com.tracepcap.intelligence.service.CustomPrivateRangeService;
import com.tracepcap.monitor.repository.NetworkChangeEventRepository;
import com.tracepcap.monitor.repository.NetworkSnapshotRepository;
import com.tracepcap.monitor.repository.SnapshotSubnetOverrideRepository;
import com.tracepcap.monitor.spi.LabelStalenessCheck;
import com.tracepcap.analysis.spi.HostClassificationLookup.HostFacts;
import com.tracepcap.monitor.entity.BaselineDefinitionEntity;
import com.tracepcap.monitor.entity.BaselineDefinitionEntity.BaselineEntryType;
import com.tracepcap.monitor.entity.NetworkChangeEventEntity;
import com.tracepcap.monitor.entity.NetworkChangeEventEntity.ChangeType;
import com.tracepcap.monitor.entity.NetworkChangeEventEntity.Severity;
import com.tracepcap.monitor.entity.NetworkEntity;
import com.tracepcap.monitor.entity.NetworkSnapshotEntity;
import com.tracepcap.monitor.repository.BaselineDefinitionRepository;
import com.tracepcap.file.entity.FileEntity;
import java.lang.reflect.Method;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Baseline definitions were declared, stored, displayed back, and never evaluated (#650). An
 * operator who baselined a gateway saw no alerts and reasonably read that as "nothing wrong", when
 * nothing had ever been compared.
 *
 * <p>These cover the two unambiguous verdicts. "Present but not declared" is deliberately absent —
 * it needs a decision on whether a baseline is an allowlist or an expectation list, which differs
 * per entry type.
 */
class BaselineDeviationDetectionTest {

  private static final UUID NETWORK = UUID.randomUUID();
  private static final UUID FILE = UUID.randomUUID();

  private final BaselineDefinitionRepository baselines = mock(BaselineDefinitionRepository.class);
  private final HostClassificationLookup hosts = mock(HostClassificationLookup.class);

  private final ChangeDetectionService service =
      new ChangeDetectionService(
          hosts, null, null, null, baselines, null, null, null, null, null, null);

  private static HostFacts host(String ip, String mac) {
    return new HostFacts(ip, mac, null, null, null, null, null, 0, List.of());
  }

  private static BaselineDefinitionEntity def(BaselineEntryType type, String key, String value) {
    BaselineDefinitionEntity d = new BaselineDefinitionEntity();
    d.setEntryType(type);
    d.setEntityKey(key);
    d.setEntityValue(value);
    return d;
  }

  private NetworkSnapshotEntity snapshot() {
    NetworkEntity network = new NetworkEntity();
    network.setId(NETWORK);
    FileEntity file = new FileEntity();
    file.setId(FILE);
    NetworkSnapshotEntity snap = new NetworkSnapshotEntity();
    snap.setNetwork(network);
    snap.setFile(file);
    snap.setSnapshotOrder(1);
    return snap;
  }

  /** The detector is private; this is the seam under test, not a public API. */
  @SuppressWarnings("unchecked")
  private List<NetworkChangeEventEntity> detect() {
    try {
      Method m =
          ChangeDetectionService.class.getDeclaredMethod(
              "detectBaselineDeviations", UUID.class, NetworkSnapshotEntity.class,
              NetworkSnapshotEntity.class);
      m.setAccessible(true);
      return (List<NetworkChangeEventEntity>) m.invoke(service, FILE, null, snapshot());
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException("detectBaselineDeviations changed — update this test", e);
    }
  }

  /** detectChanges returns whatever saveAll() hands back, so the mock has to echo its input. */
  private static NetworkChangeEventRepository savingRepository() {
    NetworkChangeEventRepository repo = mock(NetworkChangeEventRepository.class);
    when(repo.saveAll(any())).thenAnswer(inv -> new java.util.ArrayList<>(inv.getArgument(0)));
    return repo;
  }

  /** All collaborators mocked so the sibling detectors no-op instead of NPEing on nulls. */
  private ChangeDetectionService wiredService() {
    return new ChangeDetectionService(
        hosts,
        mock(ConversationLookup.class),
        mock(GeoOrgLookup.class),
        savingRepository(),
        baselines,
        mock(CustomPrivateRangeService.class),
        mock(SnapshotSubnetOverrideRepository.class),
        mock(LabelStalenessCheck.class),
        mock(NetworkSnapshotRepository.class),
        List.of(),
        mock(SubnetOverrideCarryForwardService.class));
  }

  private void observed(HostFacts... facts) {
    when(hosts.hostFacts(any())).thenReturn(List.of(facts));
  }

  private void declared(BaselineDefinitionEntity... defs) {
    when(baselines.findByNetworkIdOrderByCreatedAtAsc(NETWORK)).thenReturn(List.of(defs));
  }

  @Test
  void noDefinitions_emitsNothing() {
    declared();
    observed(host("10.0.0.1", "aa:bb:cc:dd:ee:ff"));

    assertThat(detect()).isEmpty();

    // "must not pay for it" is the half worth pinning: the short-circuit is what keeps this
    // detector free for the networks that never opened the baseline panel.
    org.mockito.Mockito.verifyNoInteractions(hosts);
  }

  @Test
  void declaredDevicePresent_emitsNothing() {
    declared(def(BaselineEntryType.DEVICE, "aa:bb:cc:dd:ee:ff", "10.0.0.1"));
    observed(host("10.0.0.1", "aa:bb:cc:dd:ee:ff"));

    assertThat(detect()).isEmpty();
  }

  @Test
  void declaredDeviceAbsent_isFlaggedAsMissing() {
    declared(def(BaselineEntryType.DEVICE, "aa:bb:cc:dd:ee:ff", "10.0.0.1"));
    observed(host("10.0.0.9", "11:22:33:44:55:66"));

    List<NetworkChangeEventEntity> events = detect();

    assertThat(events).hasSize(1);
    assertThat(events.get(0).getChangeType()).isEqualTo(ChangeType.BASELINE_MISSING);
    assertThat(events.get(0).getEntityKey()).isEqualTo("aa:bb:cc:dd:ee:ff");
  }

  @Test
  void anUppercaseMacInTheCaptureStillMatchesALowercaseDeclaration() {
    // The direction that actually needs lowerKeys(): macMap keys by the raw MAC as captured,
    // so an uppercase capture would miss a lowercase declaration entirely.
    declared(def(BaselineEntryType.DEVICE, "aa:bb:cc:dd:ee:ff", "10.0.0.1"));
    observed(host("10.0.0.1", "AA:BB:CC:DD:EE:FF"));

    assertThat(detect()).isEmpty();
  }

  @Test
  void macCasingDoesNotMakeADeclaredDeviceLookAbsent() {
    // Captures and the UI disagree on MAC casing routinely. Comparing as-is would report a
    // baselined device as missing from every snapshot it is actually in — a false alarm on
    // every ingest, which is how an operator learns to ignore the queue.
    declared(def(BaselineEntryType.DEVICE, "AA:BB:CC:DD:EE:FF", "10.0.0.1"));
    observed(host("10.0.0.1", "aa:bb:cc:dd:ee:ff"));

    assertThat(detect()).isEmpty();
  }

  @Test
  void bindingBoundToADifferentIp_isCriticalNotMerelyChanged() {
    declared(def(BaselineEntryType.IP_MAC_BINDING, "aa:bb:cc:dd:ee:ff", "10.0.0.1"));
    observed(host("10.0.0.99", "aa:bb:cc:dd:ee:ff"));

    List<NetworkChangeEventEntity> events = detect();

    // A contradicted binding is what ARP spoofing looks like, so it outranks a mere absence.
    assertThat(events).hasSize(1);
    assertThat(events.get(0).getChangeType()).isEqualTo(ChangeType.BASELINE_MISMATCH);
    assertThat(events.get(0).getSeverity()).isEqualTo(Severity.CRITICAL);
    assertThat(events.get(0).getNewValue()).containsEntry("observed", "10.0.0.99");
    assertThat(events.get(0).getNewValue()).containsEntry("expected", "10.0.0.1");
  }

  @Test
  void aDeclarationWithNoExpectedValue_onlyChecksPresence() {
    // The UI allows a key with no value. That declares "this should exist", not "it should be
    // bound to nothing" — treating a blank as a contradiction would fire on every snapshot.
    declared(def(BaselineEntryType.DEVICE, "aa:bb:cc:dd:ee:ff", ""));
    observed(host("10.0.0.99", "aa:bb:cc:dd:ee:ff"));

    assertThat(detect()).isEmpty();
  }

  @Test
  void declaredGatewayAbsent_isFlagged() {
    declared(def(BaselineEntryType.GATEWAY, "10.0.0.254", "core router"));
    observed(host("10.0.0.1", "aa:bb:cc:dd:ee:ff"));

    List<NetworkChangeEventEntity> events = detect();

    // The case the whole feature exists for: a declared gateway stops answering.
    assertThat(events).hasSize(1);
    assertThat(events.get(0).getChangeType()).isEqualTo(ChangeType.BASELINE_MISSING);
    assertThat(events.get(0).getEntityKey()).isEqualTo("10.0.0.254");
  }

  @Test
  void declaredGatewayPresent_emitsNothing() {
    declared(def(BaselineEntryType.GATEWAY, "10.0.0.254", "core router"));
    observed(host("10.0.0.254", "aa:bb:cc:dd:ee:ff"));

    assertThat(detect()).isEmpty();
  }

  @Test
  void aGatewaySeenByIpAloneIsNotReportedMissing() {
    // Not every observed host carries a MAC. Deriving "seen" from the MAC-keyed map would
    // report such a gateway absent from every snapshot it is actually in.
    declared(def(BaselineEntryType.GATEWAY, "10.0.0.254", "core router"));
    observed(host("10.0.0.254", null));

    assertThat(detect()).isEmpty();
  }

  @Test
  void protocolAndAppDeclarations_areNotEvaluatedYet() {
    // Accepted by the UI but deliberately not evaluated: they raise the same allowlist question,
    // and drift against the previous snapshot already covers them.
    declared(
        def(BaselineEntryType.PROTOCOL, "TLS", ""),
        def(BaselineEntryType.APP, "Telegram", ""),
        def(BaselineEntryType.VPN_FINGERPRINT, "wireguard", ""));
    observed(host("10.0.0.1", "aa:bb:cc:dd:ee:ff"));

    assertThat(detect()).isEmpty();
  }

  @Test
  void detectChanges_actuallyRunsTheBaselinePass() {
    // #650 was not a broken detector, it was a detector that nothing called. A unit test aimed
    // straight at the private method would still pass if the wiring were removed again, so this
    // one goes through the public entry point.
    declared(def(BaselineEntryType.DEVICE, "aa:bb:cc:dd:ee:ff", "10.0.0.1"));
    observed(host("10.0.0.9", "11:22:33:44:55:66"));

    List<NetworkChangeEventEntity> events = wiredService().detectChanges(null, snapshot());

    assertThat(events)
        .extracting(NetworkChangeEventEntity::getChangeType)
        .contains(ChangeType.BASELINE_MISSING);
  }

  @Test
  void aBlankKeyIsSkippedRatherThanFlagged() {
    declared(def(BaselineEntryType.DEVICE, "   ", "10.0.0.1"));
    observed(host("10.0.0.1", "aa:bb:cc:dd:ee:ff"));

    // An empty row in the panel is an operator mistake, not a missing device.
    assertThat(detect()).isEmpty();
  }
}
