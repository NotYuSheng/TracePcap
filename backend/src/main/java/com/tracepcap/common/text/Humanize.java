package com.tracepcap.common.text;

import java.util.Locale;

/**
 * How sizes, lengths of time and counts read in the backend's own text: answers, findings, the PDF
 * report, the LLM prompts. The single definition (#1340), in step with the frontend's {@code
 * formatBytes} and {@code formatSpan} ({@code frontend/src/utils/formatters}).
 *
 * <p>Seven byte formatters and five duration formatters used to disagree: the PDF said "1.9 MB"
 * where the Investigation said "2.0 MB" (base 1024 against base 1000), and "2 h 5 min" where the
 * vantage point said "2 h". Locale-free, so a server's locale can't turn "1.5" into "1,5".
 */
public final class Humanize {

  private Humanize() {}

  private static final String[] UNITS = {"B", "KB", "MB", "GB", "TB", "PB"};

  /**
   * "512 B", "1.50 KB", "6.00 MB", "2.10 TB": the frontend's {@code formatBytes} exactly, base
   * 1024 and two decimals past bytes. The unit is clamped at PB, and a value that rounds up to
   * 1024 of a unit moves to the next ("1.00 MB", not "1024.00 KB").
   */
  public static String bytes(long bytes) {
    String sign = bytes < 0 ? "-" : "";
    // As a double: Math.abs(Long.MIN_VALUE) is still negative.
    double value = Math.abs((double) bytes);
    if (value < 1024) return sign + (long) value + " B";
    int i = 0;
    while (i < UNITS.length - 1 && Math.round(value * 100) / 100.0 >= 1024) {
      value /= 1024;
      i++;
    }
    return sign + String.format(Locale.ROOT, "%.2f %s", value, UNITS[i]);
  }

  private static final long HOUR_MS = 3_600_000L;
  private static final double DAY_MS = 24.0 * HOUR_MS;
  private static final double MONTH_MS = 30.44 * DAY_MS;
  private static final double YEAR_MS = 365.25 * DAY_MS;

  /**
   * A length of time in the one unit that reads best: "45 s", "26 min", "5.2 h", "17 days", "3
   * months", "1.5 years". The frontend's {@code formatSpan}, rule for rule.
   */
  public static String span(long ms) {
    long ams = Math.max(0, ms);
    long s = Math.round(ams / 1000.0);
    if (s < 90) return s + " s";
    if (s < 90 * 60) return Math.round(s / 60.0) + " min";
    if (ams < 48 * HOUR_MS) return oneDecimal(ams / (double) HOUR_MS) + " h";
    if (ams < 60 * DAY_MS) return plural(Math.round(ams / DAY_MS), "day");
    if (ams < 2 * YEAR_MS) return plural(Math.round(ams / MONTH_MS), "month");
    double years = Math.round(ams / YEAR_MS * 10) / 10.0;
    return oneDecimal(ams / YEAR_MS) + " year" + (years == 1 ? "" : "s");
  }

  /** "1 conversation", "3 conversations". */
  public static String plural(long n, String noun) {
    return n + " " + noun + (n == 1 ? "" : "s");
  }

  /** "5.2", and "5" rather than "5.0", as JavaScript prints a rounded number. */
  private static String oneDecimal(double v) {
    double r = Math.round(v * 10) / 10.0;
    return r == Math.rint(r) ? Long.toString((long) r) : String.format(Locale.ROOT, "%.1f", r);
  }
}
