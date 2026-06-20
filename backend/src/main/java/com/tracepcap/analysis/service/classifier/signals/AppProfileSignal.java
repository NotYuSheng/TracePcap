package com.tracepcap.analysis.service.classifier.signals;

import com.tracepcap.analysis.service.classifier.DeviceClassificationSignal;
import com.tracepcap.analysis.service.classifier.DeviceTypes;
import com.tracepcap.analysis.service.classifier.HostContext;
import com.tracepcap.analysis.service.classifier.ScoreBoard;
import com.tracepcap.config.DeviceClassificationProperties;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * nDPI application/category profile: streaming/social apps → mobile, productivity apps →
 * laptop/desktop, server-side apps → server, IoT categories → IoT. App/category lists are
 * configurable via {@link DeviceClassificationProperties}.
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
    Set<String> iotCategories = classificationProps.getIotCategories();

    for (String app : ctx.profile().apps) {
      if (mobileApps.contains(app)) board.add(DeviceTypes.MOBILE, 20, "Mobile app \"" + app + "\" → +20");
      if (desktopApps.contains(app))
        board.add(DeviceTypes.LAPTOP_DESKTOP, 20, "Desktop app \"" + app + "\" → +20");
      if (serverApps.contains(app))
        board.add(DeviceTypes.SERVER, 20, "Server app \"" + app + "\" → +20");
    }
    for (String cat : ctx.profile().categories) {
      if (iotCategories.contains(cat)) board.add(DeviceTypes.IOT, 15, "IoT category \"" + cat + "\" → +15");
      if ("Web".equals(cat) || "Media".equals(cat))
        board.add(DeviceTypes.LAPTOP_DESKTOP, 5, cat + " category → +5");
    }
  }
}
