package com.tracepcap.config;

import java.util.LinkedHashSet;
import java.util.Set;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/** Configuration properties for device classification app/category signal lists. */
@Configuration
@ConfigurationProperties(prefix = "tracepcap.device-classification")
@Data
public class DeviceClassificationProperties {

  /** nDPI app names strongly associated with mobile devices. */
  private Set<String> mobileApps = new LinkedHashSet<>();

  /** nDPI app names suggesting a laptop or desktop. */
  private Set<String> desktopApps = new LinkedHashSet<>();

  /** nDPI app names associated with server or infrastructure roles. */
  private Set<String> serverApps = new LinkedHashSet<>();

  /** nDPI category names strongly associated with IoT / embedded devices. */
  private Set<String> iotCategories = new LinkedHashSet<>();
}
