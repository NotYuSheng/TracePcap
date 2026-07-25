package com.tracepcap.hostclassification.service.classifier.signals;

import com.tracepcap.hostclassification.service.classifier.DeviceClassificationSignal;
import com.tracepcap.hostclassification.service.classifier.DeviceTypes;
import com.tracepcap.hostclassification.service.classifier.HostContext;
import com.tracepcap.hostclassification.service.classifier.ScoreBoard;
import com.tracepcap.config.DeviceClassificationProperties;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * nDPI application/category profile: streaming/social apps → mobile, productivity apps →
 * laptop/desktop, server-side apps → server, IoT categories → IoT. App/category lists are
 * configurable via {@link DeviceClassificationProperties}.
 *
 * <p>Client-leaning app votes (mobile/desktop) score off every app the host spoke; server/IoT app
 * votes score only off apps the host was the measured responder on ({@link
 * com.tracepcap.hostclassification.service.classifier.HostProfile#servedApps}), so a host that
 * merely <em>queried</em> DNS/SMB/mDNS is not miscounted as serving them (#539).
 */
@Component
@RequiredArgsConstructor
public class AppProfileSignal implements DeviceClassificationSignal {

  private final DeviceClassificationProperties classificationProps;

  @Override
  public String name() {
    return "app-profile";
  }

  @Override
  public void contribute(HostContext ctx, ScoreBoard board) {
    Set<String> mobileApps = classificationProps.getMobileApps();
    Set<String> desktopApps = classificationProps.getDesktopApps();
    Set<String> serverApps = classificationProps.getServerApps();
    Set<String> weakServerApps = classificationProps.getWeakServerApps();
    Set<String> iotApps = classificationProps.getIotApps();
    Set<String> iotCategories = classificationProps.getIotCategories();

    // Client-leaning app names (mobile/desktop) are direction-agnostic: a host that speaks Instagram
    // is a phone whether it opened the flow or not, so score them off every observed app.
    for (String app : ctx.profile().apps) {
      if (mobileApps.contains(app)) board.add(DeviceTypes.MOBILE, 20, "Mobile app \"" + app + "\" → +20");
      if (desktopApps.contains(app))
        board.add(DeviceTypes.LAPTOP_DESKTOP, 20, "Desktop app \"" + app + "\" → +20");
    }

    // Server/IoT app names imply a SERVING host, so score them only for apps this host was the
    // measured responder on (#539). Endpoint-agnostic protocol names (DNS, SMB, MDNS, …) otherwise
    // credited the querying CLIENT too: a workstation resolving DNS collected a bogus "Server app
    // DNS" vote, an mDNS-chatty laptop collected IoT votes. A genuine server keeps its vote because
    // it answered on that app; UDP-only servers with no measured responder are still caught by their
    // detected service role (DnsServerSignal, etc.).
    for (String app : ctx.profile().servedApps) {
      if (serverApps.contains(app))
        board.add(DeviceTypes.SERVER, 20, "Served app \"" + app + "\" → +20");
      // Weak server apps (HTTP/TLS) nudge but don't decide — even when served they are ambiguous.
      if (weakServerApps.contains(app))
        board.add(DeviceTypes.SERVER, 5, "Served app \"" + app + "\" (weak server hint) → +5");
      if (iotApps.contains(app)) board.add(DeviceTypes.IOT, 20, "Served IoT app \"" + app + "\" → +20");
    }
    for (String cat : ctx.profile().categories) {
      if (iotCategories.contains(cat)) board.add(DeviceTypes.IOT, 15, "IoT category \"" + cat + "\" → +15");
      if ("Web".equals(cat) || "Media".equals(cat))
        board.add(DeviceTypes.LAPTOP_DESKTOP, 5, cat + " category → +5");
    }
  }
}
