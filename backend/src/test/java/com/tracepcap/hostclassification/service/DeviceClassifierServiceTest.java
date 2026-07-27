package com.tracepcap.hostclassification.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.analysis.entity.HostClassificationEntity;
import com.tracepcap.analysis.service.PcapParserService.ConversationInfo;
import com.tracepcap.config.DeviceClassificationProperties;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.hostclassification.service.classifier.DeviceTypes;
import com.tracepcap.hostclassification.service.classifier.signals.AppProfileSignal;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * End-to-end guard for the measured-serving direction wiring (#539): a reversed or omitted
 * {@code servedApps.add()} in {@link DeviceClassifierService#classify} would sail past the
 * signal-level {@link com.tracepcap.hostclassification.service.classifier.signals.AppProfileSignalTest}
 * (which builds profiles by hand), so exercise a real flow through {@code classify} and assert only
 * the measured responder is credited with serving the app.
 */
class DeviceClassifierServiceTest {

  private static final String CLIENT_IP = "10.0.0.10";
  private static final String SERVER_IP = "10.0.0.53";

  private DeviceClassifierService service() {
    DeviceClassificationProperties props = new DeviceClassificationProperties();
    props.setServerApps(Set.of("DNS"));
    return new DeviceClassifierService(List.of(new AppProfileSignal(props)));
  }

  /** One TCP DNS flow the client opened toward the server (measured initiator = client). */
  private ConversationInfo dnsFlow() {
    ConversationInfo conv = new ConversationInfo();
    conv.setSrcIp(CLIENT_IP); // sorts first; NOT a direction claim
    conv.setSrcPort(54321);
    conv.setDstIp(SERVER_IP);
    conv.setDstPort(53);
    conv.setInitiatorIp(CLIENT_IP); // client sent SYN → server is the responder
    conv.setAppName("DNS");
    conv.setPacketCount(10L);
    conv.setTotalBytes(2000L);
    return conv;
  }

  private HostClassificationEntity classifyAndGet(String ip) {
    List<HostClassificationEntity> results =
        service()
            .classify(
                FileEntity.builder().build(),
                List.of(dnsFlow()),
                Map.of(),
                Map.of(),
                Map.of(),
                Map.of(),
                Map.of());
    return results.stream().filter(h -> ip.equals(h.getIp())).findFirst().orElseThrow();
  }

  @Test
  void responder_isCreditedWithServingTheApp() {
    HostClassificationEntity server = classifyAndGet(SERVER_IP);

    assertThat(server.getDeviceType()).isEqualTo(DeviceTypes.SERVER);
    assertThat(server.getWinnerReasons()).contains("Served app \"DNS\"");
  }

  @Test
  void initiator_isNotCreditedWithServingTheApp() {
    // The client spoke DNS but never answered it: the server-app vote must not reach it (#539).
    HostClassificationEntity client = classifyAndGet(CLIENT_IP);

    assertThat(client.getDeviceType()).isNotEqualTo(DeviceTypes.SERVER);
    // winnerReasons is null when a host gathered no votes at all — guard the null before asserting.
    assertThat(String.valueOf(client.getWinnerReasons())).doesNotContain("Served app");
  }
}
