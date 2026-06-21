package com.tracepcap.analysis.spi;

import com.tracepcap.file.entity.FileEntity;
import java.io.File;

/**
 * Extracts a per-host "service activity log" for hosts acting in a particular server role.
 *
 * <p>This is the reusable seam behind the Network Intelligence per-host service views. DNS is the
 * first implementation ({@code DnsQueryLogExtractor}, surfacing which domains a DNS server resolves
 * and which fail); future roles — e.g. an HTTP/API endpoint log for web servers — implement this
 * same contract and are picked up automatically.
 *
 * <p>Each implementation owns its own table, entity, repository and tshark pass — protocols have
 * genuinely different schemas, so there is no shared polymorphic table. The shared contract is
 * simply: run one read-only tshark pass over the capture, persist your rows, and report which
 * server IPs look suspicious.
 *
 * <p>{@code AnalysisService} injects {@code List<HostServiceLogExtractor>} (Spring collects every
 * bean) and runs them all during analysis, so adding a new role requires no change to the pipeline.
 * Implementations must degrade gracefully and never throw — on any failure they should persist
 * whatever they extracted (possibly nothing) and return an empty suspicion list.
 */
public interface HostServiceLogExtractor {

  /** Stable role identifier, e.g. {@code "dns"} (later {@code "http"}). Used for logging/routing. */
  String role();

  /**
   * Runs the extraction over {@code pcap}, persists the resulting rows linked to {@code file}, and
   * returns which hosts served this role plus any that behaved anomalously.
   */
  HostServiceLogResult extractAndPersist(FileEntity file, File pcap);
}
