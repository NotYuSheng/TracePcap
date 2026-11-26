package com.tracepcap.common.settings;

import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
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
      "At once in a DNS server's DNS tab; host DNS logs use it from the next analysis."),
  DNS_NXDOMAIN_MIN_QUERIES(Kind.DETECTION, Type.INT, 1, 1_000_000,
      "At once in a DNS server's DNS tab; host DNS logs use it from the next analysis."),
  HTTP_CLIENT_ERROR_SUSPICIOUS_RATIO(Kind.DETECTION, Type.RATIO, 0, 1,
      "At once in a web server's HTTP tab."),
  HTTP_MIN_REQUESTS(Kind.DETECTION, Type.INT, 1, 1_000_000,
      "At once in a web server's HTTP tab."),

  // The LLM connection: read on every call, so a change applies to the next one.
  LLM_API_BASE_URL(Kind.LLM, Type.URL, 0, 0, "From the next LLM call."),
  LLM_API_KEY(Kind.LLM, Type.SECRET, 0, 0, "From the next LLM call."),
  LLM_MODEL(Kind.LLM, Type.TEXT, 0, 0, "From the next LLM call."),
  LLM_TEMPERATURE(Kind.LLM, Type.DECIMAL, 0, 2, "From the next LLM call."),
  LLM_MAX_TOKENS(Kind.LLM, Type.INT, 0, 1_000_000, "From the next LLM call."),
  LLM_TIMEOUT(Kind.LLM, Type.INT, 5, 7_200, "From the next LLM call."),
  LLM_TOOL_CALLING(Kind.LLM, Type.CHOICE, 0, 0, "From the next story.", "auto", "on", "off");

  /** Which permission governs it. Retention deletes data, so it has its own (admin by default). */
  public enum Kind {
    RETENTION,
    DETECTION,
    /** The LLM connection: where Story and Insights send captures' details. Admin by default. */
    LLM
  }

  public enum Type {
    INT,
    /** A number from 0 to 1. */
    RATIO,
    /** A number between min and max, with decimals. */
    DECIMAL,
    /** Free text on one line, such as a model name. */
    TEXT,
    /** An http(s) URL. */
    URL,
    /** Never shown back once set; the audit log records only that it changed. */
    SECRET,
    /** One of a fixed set of words. */
    CHOICE
  }

  private final Kind kind;
  private final Type type;
  private final double min;
  private final double max;
  private final String takesEffect;
  private final List<String> choices;

  EditablePolicy(Kind kind, Type type, double min, double max, String takesEffect, String... choices) {
    this.kind = kind;
    this.type = type;
    this.min = min;
    this.max = max;
    this.takesEffect = takesEffect;
    this.choices = List.of(choices);
  }

  public Kind kind() {
    return kind;
  }

  public Type type() {
    return type;
  }

  public boolean secret() {
    return type == Type.SECRET;
  }

  /** The allowed values of a {@link Type#CHOICE}; empty otherwise. */
  public List<String> choices() {
    return choices;
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
    switch (type) {
      case TEXT -> {
        if (v.isEmpty() || v.length() > 255 || v.contains("\n")) {
          throw new IllegalArgumentException("Enter a value on one line, up to 255 characters.");
        }
        return v;
      }
      case SECRET -> {
        if (v.isEmpty() || v.length() > 4096) {
          throw new IllegalArgumentException("Enter the key, up to 4096 characters.");
        }
        return v;
      }
      case URL -> {
        try {
          URI u = URI.create(v);
          String scheme = u.getScheme() == null ? "" : u.getScheme().toLowerCase(Locale.ROOT);
          if (!(scheme.equals("http") || scheme.equals("https")) || u.getHost() == null) {
            throw new IllegalArgumentException("x");
          }
        } catch (IllegalArgumentException e) {
          throw new IllegalArgumentException(
              "Enter an http:// or https:// address, such as http://10.0.0.5:1234/v1.");
        }
        // The client appends /models and /chat/completions itself.
        return v.replaceAll("/+$", "");
      }
      case CHOICE -> {
        String c = v.toLowerCase(Locale.ROOT);
        if (!choices.contains(c)) {
          throw new IllegalArgumentException("Choose one of: " + String.join(", ", choices) + ".");
        }
        return c;
      }
      default -> {
        // numbers
      }
    }
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
      throw outOfRange();
    }
  }

  private IllegalArgumentException outOfRange() {
    return new IllegalArgumentException(
        switch (type) {
          case INT -> "Enter a whole number from " + (long) min + " to " + (long) max + ".";
          case DECIMAL -> "Enter a number from " + min + " to " + max + ", such as 0.7.";
          default -> "Enter a number from 0 to 1, such as 0.5.";
        });
  }
}
