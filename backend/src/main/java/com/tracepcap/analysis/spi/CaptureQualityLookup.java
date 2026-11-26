package com.tracepcap.analysis.spi;

import java.util.List;
import java.util.UUID;

/**
 * Read port for how complete a capture is (#1268): the notes the Overview's capture-quality card
 * shows, for modules outside {@code analysis} (the investigation framework's Completeness category).
 */
public interface CaptureQualityLookup {

  /**
   * One thing worth saying about a capture's completeness.
   *
   * @param kind a stable key: "gaps", "midstream", "memcap", "suricata-unread", "invalid", "depth"
   * @param level "warning" when traffic is missing or uninspected, "info" otherwise
   */
  record QualityNote(String kind, String level, String text) {}

  /** The notes for a capture, most consequential first; empty when nothing is worth saying. */
  List<QualityNote> qualityNotes(UUID fileId);
}
