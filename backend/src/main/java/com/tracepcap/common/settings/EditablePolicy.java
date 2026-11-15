package com.tracepcap.common.settings;

import java.util.Arrays;
import java.util.Optional;

/**
 * The deploy-time settings that can be overridden in the app (#915 phase 5), with how each is
 * validated. Everything else in {@link SystemSettingsCatalog} stays deploy-time on purpose: it's
 * infrastructure, tied to memory sizing, or (like FILE_RETENTION_ENABLED) decides at startup
 * whether a component exists at all.
 */
public enum EditablePolicy {
  FILE_RETENTION_HOURS(Kind.RETENTION, Type.INT, 1, 87_600,
      "From the next cleanup run (hourly)."),
  MONITOR_FILE_RETENTION_HOURS(Kind.RETENTION, Type.INT, 0, 87_600,
      "From the next cleanup run (hourly). 0 keeps monitor captures forever."),
  PACKET_RETENTION_HOURS(Kind.RETENTION, Type.INT, 0, 87_600,
      "From the next cleanup run (hourly). 0 keeps raw packets as long as the capture."),
  DNS_NXDOMAIN_SUSPICIOUS_RATIO(Kind.DETECTION, Type.RATIO, 0, 1,
      "At once in the network cluster view; host DNS logs use it from the next analysis."),
  DNS_NXDOMAIN_MIN_QUERIES(Kind.DETECTION, Type.INT, 1, 1_000_000,
      "At once in the network cluster view; host DNS logs use it from the next analysis."),
  HTTP_CLIENT_ERROR_SUSPICIOUS_RATIO(Kind.DETECTION, Type.RATIO, 0, 1,
      "At once in the network cluster view."),
  HTTP_MIN_REQUESTS(Kind.DETECTION, Type.INT, 1, 1_000_000,
      "At once in the network cluster view.");

  /** Which permission governs it. Retention deletes data, so it has its own (admin by default). */
  public enum Kind {
    RETENTION,
    DETECTION
  }

  public enum Type {
    INT,
    /** A number from 0 to 1. */
    RATIO
  }

  private final Kind kind;
  private final Type type;
  private final double min;
  private final double max;
  private final String takesEffect;

  EditablePolicy(Kind kind, Type type, double min, double max, String takesEffect) {
    this.kind = kind;
    this.type = type;
    this.min = min;
    this.max = max;
    this.takesEffect = takesEffect;
  }

  public Kind kind() {
    return kind;
  }

  public String takesEffect() {
    return takesEffect;
  }

  public static Optional<EditablePolicy> of(String key) {
    return Arrays.stream(values()).filter(p -> p.name().equals(key)).findFirst();
  }

  /**
   * Checks and normalises a value typed in the app, or throws IllegalArgumentException (400) with
   * a message the UI shows as is.
   */
  public String normalise(String raw) {
    String v = raw == null ? "" : raw.trim();
    try {
      if (type == Type.INT) {
        long n = Long.parseLong(v);
        if (n < min || n > max) throw outOfRange();
        return Long.toString(n);
      }
      double d = Double.parseDouble(v);
      if (Double.isNaN(d) || d < min || d > max) throw outOfRange();
      return Double.toString(d);
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException(
          type == Type.INT ? "Enter a whole number." : "Enter a number from 0 to 1, such as 0.5.");
    }
  }

  private IllegalArgumentException outOfRange() {
    return new IllegalArgumentException(
        type == Type.INT
            ? "Enter a whole number from " + (long) min + " to " + (long) max + "."
            : "Enter a number from 0 to 1, such as 0.5.");
  }
}
