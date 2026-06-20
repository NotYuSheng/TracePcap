package com.tracepcap.analysis.service.classifier;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Accumulates weighted votes from {@link DeviceClassificationSignal}s for a single host. Each signal
 * calls {@link #add(String, int, String)} to contribute points (and a human-readable reason) toward
 * a device type; the board then reports the winning type, a margin-based confidence, and the reasons
 * behind any type.
 *
 * <p>Device types are plain strings, so adding a new type requires no change here — a signal simply
 * starts voting for it.
 */
public class ScoreBoard {

  private final Map<String, Integer> scores = new LinkedHashMap<>();
  private final Map<String, List<String>> reasons = new LinkedHashMap<>();

  /** Adds {@code weight} points (and an explanatory reason) toward {@code deviceType}. */
  public void add(String deviceType, int weight, String reason) {
    if (deviceType == null || weight == 0) return;
    scores.merge(deviceType, weight, Integer::sum);
    reasons.computeIfAbsent(deviceType, k -> new ArrayList<>()).add(reason);
  }

  /** Raw per-type scores (mutable view not exposed; copy returned). */
  public Map<String, Integer> scores() {
    return new LinkedHashMap<>(scores);
  }

  /** The highest-scoring device type, or {@code fallback} when nothing scored above zero. */
  public String winner(String fallback) {
    return scores.entrySet().stream()
        .max(Map.Entry.comparingByValue())
        .filter(e -> e.getValue() > 0)
        .map(Map.Entry::getKey)
        .orElse(fallback);
  }

  /** Reasons that voted for the given type, in the order they fired. */
  public List<String> reasonsFor(String deviceType) {
    return reasons.getOrDefault(deviceType, List.of());
  }

  /**
   * Margin-based confidence (0–100): the gap between the best and second-best scores, clamped to
   * {@code [0, marginForFull]} and scaled to a percentage. A large margin = unambiguous; a small
   * margin = conflicted signals.
   */
  public int confidence(int marginForFull) {
    List<Integer> sorted =
        scores.values().stream().sorted(Comparator.reverseOrder()).toList();
    if (sorted.isEmpty() || sorted.get(0) == 0) return 0;
    int best = sorted.get(0);
    int second = sorted.size() > 1 ? sorted.get(1) : 0;
    int margin = best - second;
    return Math.min(100, (int) Math.round(margin * 100.0 / marginForFull));
  }
}
