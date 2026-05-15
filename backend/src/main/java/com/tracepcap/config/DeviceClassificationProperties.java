package com.tracepcap.config;

import jakarta.validation.constraints.NotNull;
import java.util.LinkedHashSet;
import java.util.Set;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

/** Configuration properties for device classification app/category signal lists. */
@Configuration
@ConfigurationProperties(prefix = "tracepcap.device-classification")
@Validated
@Data
public class DeviceClassificationProperties {

  /** nDPI app names strongly associated with mobile devices. */
  @NotNull
  private Set<String> mobileApps = new LinkedHashSet<>();

  /** nDPI app names suggesting a laptop or desktop. */
  @NotNull
  private Set<String> desktopApps = new LinkedHashSet<>();

  /** nDPI app names associated with server or infrastructure roles. */
  @NotNull
  private Set<String> serverApps = new LinkedHashSet<>();

  /** nDPI category names strongly associated with IoT / embedded devices. */
  @NotNull
  private Set<String> iotCategories = new LinkedHashSet<>();
}
