package com.tracepcap.analysis.spi;

import com.tracepcap.analysis.service.PcapParserService;
import com.tracepcap.file.entity.FileEntity;
import java.io.File;
import java.util.List;
import java.util.UUID;

/**
 * The capture an {@link Extractor} is working on, and the working set it writes into (#512).
 *
 * <p><b>The conversations are mutable, and that is the point.</b> Extract's job is to fill them in:
 * an extractor calls {@code setAppName}, {@code setFlowRisks}, {@code setHostname} on the objects it
 * finds facts for, and the pipeline persists the result once every extractor has had its turn.
 * That is the opposite of Scan, where the facts are immutable records and a scanner that could
 * mutate them would be corrupting the evidence it reasons about.
 *
 * <p>The list is shared: each extractor sees what earlier ones wrote. That is deliberate — tshark
 * enrichment reads what nDPI populated — but it means an extractor that <em>overwrites</em> a peer's
 * field rather than adding its own destroys a fact nobody can recover. Add; do not overwrite.
 */
public interface ExtractionTarget {

  /** The file being analysed. */
  UUID fileId();

  /**
   * The capture on local disk.
   *
   * <p>Extract is one of the few stages permitted to read this at all (Ingest and evidence export
   * are the others) — everything downstream reads the database. The file is a temporary copy and is
   * gone once analysis finishes, so an extractor must take what it needs now.
   */
  File capture();

  /**
   * The conversations parsed from the capture, <b>mutable and shared</b> — the working set to write
   * facts onto. Never null; empty for a capture with no conversations, in which case most extractors
   * have nothing to do.
   */
  List<PcapParserService.ConversationInfo> conversations();

  /**
   * The file record, for extractors whose {@link Extractor#enabledFor} depends on how it was
   * uploaded (per-file toggles like {@code enableNdpi}, size, source).
   */
  FileEntity file();
}
