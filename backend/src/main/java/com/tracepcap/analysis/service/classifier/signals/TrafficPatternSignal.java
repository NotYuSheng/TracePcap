package com.tracepcap.analysis.service.classifier.signals;

import com.tracepcap.analysis.service.classifier.DeviceClassificationSignal;
import com.tracepcap.analysis.service.classifier.DeviceTypes;
import com.tracepcap.analysis.service.classifier.HostContext;
import com.tracepcap.analysis.service.classifier.HostProfile;
import com.tracepcap.analysis.service.classifier.ScoreBoard;
import org.springframework.stereotype.Component;

/**
 * Behavioural traffic patterns: high peer fan-out → router; inbound-only on well-known ports →
 * server; low variety + low volume → IoT; mostly-outbound with varied apps → mobile/laptop;
 * DNS/NTP-only → infra (router/server).
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

    // Only receives on well-known ports, never initiates → server.
    boolean receivesOnWellKnown = p.receivedOnPorts.stream().anyMatch(port -> port < 1024);
    boolean neverInitiates = p.initiatedCount == 0;
    if (neverInitiates && receivesOnWellKnown) {
      board.add(DeviceTypes.SERVER, 35, "Inbound-only on a well-known port → +35");
    } else if (neverInitiates) {
      board.add(DeviceTypes.SERVER, 15, "Never initiates connections → +15");
    }

    // Low variety + low volume → IoT.
    if (p.apps.size() <= 2 && p.conversationCount <= 5 && p.totalPackets < 200) {
      board.add(DeviceTypes.IOT, 20, "Low app variety + low volume → +20");
    }

    // Mostly initiates traffic (client-like) with varied apps → mobile/laptop.
    double initiateRatio =
        p.conversationCount > 0 ? (double) p.initiatedCount / p.conversationCount : 0;
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
