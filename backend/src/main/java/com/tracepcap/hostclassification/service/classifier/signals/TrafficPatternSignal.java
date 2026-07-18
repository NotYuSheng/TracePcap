package com.tracepcap.hostclassification.service.classifier.signals;

import com.tracepcap.hostclassification.service.classifier.DeviceClassificationSignal;
import com.tracepcap.hostclassification.service.classifier.DeviceTypes;
import com.tracepcap.hostclassification.service.classifier.HostContext;
import com.tracepcap.hostclassification.service.classifier.HostProfile;
import com.tracepcap.hostclassification.service.classifier.ScoreBoard;
import org.springframework.stereotype.Component;

/**
 * Behavioural traffic patterns: high peer fan-out → router; answers connections it never opens (by
 * the MEASURED initiator, #496) → server; low variety + low volume → IoT; mostly-opens with varied
 * apps → mobile/laptop; DNS/NTP-only → infra (router/server).
 */
@Component
public class TrafficPatternSignal implements DeviceClassificationSignal {

  @Override
  public String name() {
    return "traffic-pattern";
  }

  @Override
  public void contribute(HostContext ctx, ScoreBoard board) {
    HostProfile p = ctx.profile();

    // High peer count → likely router.
    if (p.peers.size() >= 15) {
      board.add(DeviceTypes.ROUTER, 35, p.peers.size() + " peers (high fan-out) → +35");
    } else if (p.peers.size() >= 8) {
      board.add(DeviceTypes.ROUTER, 15, p.peers.size() + " peers (moderate fan-out) → +15");
    }

    // Answers connections but never opens one → server. Direction is the MEASURED initiator (#496),
    // not srcIp/dstIp; a host with only direction-unknown flows (measuredResponses == 0) is NOT
    // voted server by default. A well-known responding port strengthens but no longer decides.
    boolean answersButNeverInitiates = p.measuredResponses > 0 && p.measuredInitiations == 0;
    boolean respondsOnWellKnown = p.respondedOnPorts.stream().anyMatch(port -> port < 1024);
    if (answersButNeverInitiates && respondsOnWellKnown) {
      board.add(DeviceTypes.SERVER, 35, "Answers connections it never opens, on a well-known port → +35");
    } else if (answersButNeverInitiates) {
      board.add(DeviceTypes.SERVER, 15, "Answers connections it never opens → +15");
    }

    // Low variety + low volume → IoT.
    if (p.apps.size() <= 2 && p.conversationCount <= 5 && p.totalPackets < 200) {
      board.add(DeviceTypes.IOT, 20, "Low app variety + low volume → +20");
    }

    // Mostly opens connections (client-like) with varied apps → mobile/laptop. Ratio is over MEASURED
    // flows only (#496) — flows with no known initiator can neither confirm nor deny client-ness.
    int measuredFlows = p.measuredInitiations + p.measuredResponses;
    double initiateRatio = measuredFlows > 0 ? (double) p.measuredInitiations / measuredFlows : 0;
    if (initiateRatio > 0.7 && p.apps.size() > 3) {
      board.add(DeviceTypes.MOBILE, 10, "Mostly-outbound with varied apps → +10");
      board.add(DeviceTypes.LAPTOP_DESKTOP, 10, "Mostly-outbound with varied apps → +10");
    }

    // DNS/NTP only → router/server infrastructure.
    boolean onlyInfraApps =
        !p.apps.isEmpty()
            && p.apps.stream().allMatch(a -> a.equalsIgnoreCase("DNS") || a.equalsIgnoreCase("NTP"));
    if (onlyInfraApps) {
      board.add(DeviceTypes.ROUTER, 20, "Only DNS/NTP traffic → +20");
      board.add(DeviceTypes.SERVER, 15, "Only DNS/NTP traffic → +15");
    }
  }
}
