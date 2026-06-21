package com.tracepcap.hostclassification.service.classifier;

/**
 * Canonical device-type identifiers a {@link DeviceClassificationSignal} can vote for. Plain string
 * constants — adding a new type is just a new constant plus a signal that votes for it (and a
 * matching label/icon on the frontend). A YAML {@code device_type} override may also set an arbitrary
 * custom value that passes through unchanged.
 */
public final class DeviceTypes {

  private DeviceTypes() {}

  public static final String ROUTER = "ROUTER";
  public static final String MOBILE = "MOBILE";
  public static final String LAPTOP_DESKTOP = "LAPTOP_DESKTOP";
  public static final String SERVER = "SERVER";
  public static final String IOT = "IOT";
  public static final String DNS_SERVER = "DNS_SERVER";
  public static final String WEB_SERVER = "WEB_SERVER";
  public static final String API_SERVER = "API_SERVER";
  public static final String UNKNOWN = "UNKNOWN";
}
