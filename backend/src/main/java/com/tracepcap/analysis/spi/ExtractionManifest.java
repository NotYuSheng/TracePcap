package com.tracepcap.analysis.spi;

import java.util.Optional;
import java.util.UUID;

/**
 * Read port for the extraction run manifest (#512 slice 2): per file and per extractor, whether
 * extraction COMPLETED, FAILED, or was SKIPPED. Lives in the SPI so downstream consumers (story
 * detectors, scanners) depend on this contract rather than on the {@code analysis} module's
 * repositories.
 *
 * <p>Consumers must distinguish three situations: a run that says COMPLETED (absence of a fact is
 * meaningful), a run that says FAILED/SKIPPED (absence of a fact is a coverage gap, not a
 * finding), and <b>no row at all</b> — files analysed before the manifest existed have no rows,
 * and their extraction provenance is simply unknown.
 */
public interface ExtractionManifest {

  /** Well-known extractor names recorded by the pipeline. */
  String NDPI = "ndpi";

  String TSHARK_ENRICHMENT = "tshark-enrichment";
  String SURICATA = "suricata";

  enum Status {
    /** The extractor ran to completion; its silence about a flow is meaningful. */
    COMPLETED,
    /** The extractor started but did not finish cleanly; facts may be missing. */
    FAILED,
    /** The extractor was not run (feature flag off, tool not installed). */
    SKIPPED
  }

  /** One recorded run. {@code detail} is a short human-readable reason, mainly for non-COMPLETED. */
  record Run(String extractor, String version, Status status, String detail) {}

  /** The recorded run for this file+extractor, or empty when the file predates the manifest. */
  Optional<Run> runFor(UUID fileId, String extractor);
}
