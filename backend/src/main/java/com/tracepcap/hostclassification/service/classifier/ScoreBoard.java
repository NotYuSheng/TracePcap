package com.tracepcap.hostclassification.service.classifier;

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

  /**
   * Takes back points (and the reason given with them) toward {@code deviceType}: used when a
   * stored board is re-scored after a detection rule's vote changed (#925). A type left with no
   * points and no reasons is dropped.
   */
  public void remove(String deviceType, int weight, String reason) {
    if (deviceType == null || weight == 0) return;
    scores.computeIfPresent(deviceType, (k, v) -> v - weight);
    List<String> r = reasons.get(deviceType);
    if (r != null) {
      r.remove(reason);
      if (r.isEmpty()) reasons.remove(deviceType);
    }
    Integer left = scores.get(deviceType);
    if (left != null && left == 0 && !reasons.containsKey(deviceType)) scores.remove(deviceType);
  }

  /** A board rebuilt from stored scores and reasons. */
  public static ScoreBoard of(Map<String, Integer> scores, Map<String, List<String>> reasons) {
    ScoreBoard b = new ScoreBoard();
    if (scores != null) b.scores.putAll(scores);
    if (reasons != null) reasons.forEach((k, v) -> b.reasons.put(k, new ArrayList<>(v)));
    return b;
  }

  /** Every type's reasons (copied). */
  public Map<String, List<String>> allReasons() {
    Map<String, List<String>> out = new LinkedHashMap<>();
    reasons.forEach((k, v) -> out.put(k, List.copyOf(v)));
    return out;
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

  /**
   * The second-highest-scoring type and its score, or {@code null} when fewer than two types
   * scored above zero. Persisted with the winner so adjudication (#512 slice 5) can see how close
   * second place was — a walkover and a knife-edge are different answers.
   */
  public Map.Entry<String, Integer> runnerUp() {
    return scores.entrySet().stream()
        .filter(e -> e.getValue() > 0)
        .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
        .skip(1)
        .findFirst()
        .orElse(null);
  }

  /** Reasons that voted for the given type, in the order they fired (defensive copy). */
  public List<String> reasonsFor(String deviceType) {
    return List.copyOf(reasons.getOrDefault(deviceType, List.of()));
  }

  /**
   * Margin-based confidence (0–100): the gap between the best and second-best scores, clamped to
   * {@code [0, marginForFull]} and scaled to a percentage. A large margin = unambiguous; a small
   * margin = conflicted signals.
   */
  public int confidence(int marginForFull) {
    if (marginForFull <= 0) return 100; // degenerate config — any positive margin is "full"
    List<Integer> sorted =
        scores.values().stream().sorted(Comparator.reverseOrder()).toList();
    if (sorted.isEmpty() || sorted.get(0) == 0) return 0;
    int best = sorted.get(0);
    int second = sorted.size() > 1 ? sorted.get(1) : 0;
    int margin = best - second;
    return Math.min(100, (int) Math.round(margin * 100.0 / marginForFull));
  }
}
