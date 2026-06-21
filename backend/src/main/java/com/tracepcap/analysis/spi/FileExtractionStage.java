package com.tracepcap.analysis.spi;

import com.tracepcap.file.entity.FileEntity;
import java.io.File;
import java.util.List;
import java.util.UUID;

/**
 * Port for the optional file-carving stage of the analysis pipeline.
 *
 * <p>Defined in {@code analysis} (the ingest core) and implemented by the {@code extraction} feature
 * module, so the pipeline depends on this abstraction rather than on the concrete service. Invoked
 * after conversations and packets are persisted, and only when file extraction is enabled for the
 * file.
 */
public interface FileExtractionStage {

  /**
   * Carves files out of the captured traffic and persists them, associating each with its source
   * conversation.
   *
   * @param file the file record being analysed
   * @param pcapFile the downloaded PCAP on local disk
   * @param conversationIds ids of the conversations persisted for this file, in capture order
   */
  void extractFiles(FileEntity file, File pcapFile, List<UUID> conversationIds);
}
