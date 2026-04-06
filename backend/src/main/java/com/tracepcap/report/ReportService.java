package com.tracepcap.report;

import com.lowagie.text.Document;
import com.lowagie.text.Element;
import com.lowagie.text.Font;
import com.lowagie.text.Image;
import com.lowagie.text.PageSize;
import com.lowagie.text.Paragraph;
import com.lowagie.text.Phrase;
import com.lowagie.text.Rectangle;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfWriter;
import com.tracepcap.analysis.entity.AnalysisResultEntity;
import com.tracepcap.analysis.entity.ConversationEntity;
import com.tracepcap.analysis.entity.ExtractedFileEntity;
import com.tracepcap.analysis.entity.HostClassificationEntity;
import com.tracepcap.analysis.repository.AnalysisResultRepository;
import com.tracepcap.analysis.repository.ConversationRepository;
import com.tracepcap.analysis.repository.ExtractedFileRepository;
import com.tracepcap.analysis.repository.HostClassificationRepository;
import com.tracepcap.analysis.repository.IpGeoInfoRepository;
import com.tracepcap.common.exception.ResourceNotFoundException;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.repository.FileRepository;
import java.awt.Color;
import java.io.OutputStream;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class ReportService {

  // ── limits ────────────────────────────────────────────────────────────────
  private static final int TOP_CONVERSATIONS_LIMIT = 30;
  private static final int SECURITY_FINDINGS_LIMIT = 100;
  private static final int TLS_LIMIT = 50;

  // ── PDF colours ───────────────────────────────────────────────────────────
  private static final Color C_HEADER_BG = new Color(30, 64, 175);
  private static final Color C_SUBHEADER_BG = new Color(59, 130, 246);
  private static final Color C_ROW_ALT = new Color(239, 246, 255);
  private static final Color C_RISK_BG = new Color(254, 226, 226);
  private static final Color C_DIVIDER = new Color(147, 197, 253);
  private static final Color C_TEXT = new Color(30, 41, 59);
  private static final Color C_LABEL = new Color(30, 41, 59);

  // ── date/time format ──────────────────────────────────────────────────────
  private static final DateTimeFormatter DT_FMT =
      DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss");

  // ── repositories ──────────────────────────────────────────────────────────
  private final FileRepository fileRepository;
  private final AnalysisResultRepository analysisResultRepository;
  private final ConversationRepository conversationRepository;
  private final HostClassificationRepository hostClassificationRepository;
  private final ExtractedFileRepository extractedFileRepository;
  private final IpGeoInfoRepository ipGeoInfoRepository;

  // ══════════════════════════════════════════════════════════════════════════
  // Public entry point
  // ══════════════════════════════════════════════════════════════════════════

  @Transactional(readOnly = true)
  public void generateReport(UUID fileId, ReportRequest request, OutputStream out) {
    FileEntity file =
        fileRepository
            .findById(fileId)
            .orElseThrow(() -> new ResourceNotFoundException("File not found: " + fileId));

    AnalysisResultEntity analysis = analysisResultRepository.findByFileId(fileId).orElse(null);

    List<HostClassificationEntity> hosts = hostClassificationRepository.findByFileId(fileId);

    List<ConversationEntity> topConversations =
        conversationRepository.findTopByFileIdOrderByTotalBytesDesc(
            fileId, PageRequest.of(0, TOP_CONVERSATIONS_LIMIT));
    List<ConversationEntity> riskyConversations =
        conversationRepository.findAtRiskByFileIdLimited(fileId, SECURITY_FINDINGS_LIMIT);
    List<ConversationEntity> tlsConversations =
        conversationRepository.findConversationsWithTlsByFileId(
            fileId, PageRequest.of(0, TLS_LIMIT));

    List<ExtractedFileEntity> extractedFiles =
        extractedFileRepository.findByFileIdOrderByCreatedAtAsc(fileId);

    List<Object[]> appStats = conversationRepository.findApplicationStatsByFileId(fileId);
    List<Object[]> l7Stats = conversationRepository.findL7ProtocolStatsByFileId(fileId);
    List<Object[]> categoryStats = conversationRepository.findCategoryDistributionByFileId(fileId);

    List<String> fileTypes = conversationRepository.findDistinctFileTypesByFileId(fileId);
    List<String> httpUserAgents = conversationRepository.findDistinctHttpUserAgentsByFileId(fileId);
    List<String> riskTypes = conversationRepository.findDistinctRiskTypesByFileId(fileId);
    List<String> customSigs = conversationRepository.findDistinctCustomSignaturesByFileId(fileId);

    List<Object[]> geoCountries = ipGeoInfoRepository.findDistinctCountriesByFileId(fileId);

    long totalConversations = conversationRepository.countByFileId(fileId);
    long riskCount = conversationRepository.countAtRiskByFileId(fileId);

    Document document = new Document(PageSize.A4, 40, 40, 60, 40);
    try {
      PdfWriter.getInstance(document, out);
      document.open();

      // ── Sections ──────────────────────────────────────────────────────────
      // Section counter: increment only for sections that are actually emitted
      // so numbering stays consecutive even when optional sections are skipped.
      int sec = 1;
      addCover(document, file);
      addFileInfo(document, file, sec++);
      addExecutiveSummary(
          document,
          file,
          analysis,
          hosts.size(),
          totalConversations,
          riskCount,
          extractedFiles.size(),
          geoCountries.size(),
          sec++);

      if (analysis != null && analysis.getProtocolStats() != null) {
        addProtocolDistribution(document, analysis.getProtocolStats(), sec++);
      }

      if (!categoryStats.isEmpty()) {
        addCategoryDistribution(document, categoryStats, sec++);
      }

      if (!appStats.isEmpty()) {
        addApplicationsDetected(document, appStats, sec++);
      }

      if (!l7Stats.isEmpty()) {
        addL7Protocols(document, l7Stats, sec++);
      }

      addHostInventory(document, hosts, sec++);

      if (!geoCountries.isEmpty()) {
        addGeoSummary(document, geoCountries, sec++);
      }

      if (!riskTypes.isEmpty() || !customSigs.isEmpty()) {
        addRiskTypeSummary(document, riskTypes, customSigs, sec++);
      }

      if (!riskyConversations.isEmpty()) {
        addSecurityFindings(document, riskyConversations, sec++);
      }

      if (!tlsConversations.isEmpty()) {
        addTlsAnalysis(document, tlsConversations, sec++);
      }

      if (!httpUserAgents.isEmpty()) {
        addHttpUserAgents(document, httpUserAgents, sec++);
      }

      if (!topConversations.isEmpty()) {
        addTopConversations(document, topConversations, sec++);
      }

      if (!fileTypes.isEmpty()) {
        addDetectedFileTypes(document, fileTypes, sec++);
      }

      if (!extractedFiles.isEmpty()) {
        addExtractedFiles(document, extractedFiles, sec++);
      }

      addTopologyDiagram(document, request.getForceDirectedImage(), "Force-Directed Layout", sec++);
      addTopologyDiagram(
          document, request.getHierarchicalImage(), "Hierarchical Layout (Top-Down)", sec++);

    } catch (Exception e) {
      log.error("PDF generation failed for file {}", fileId, e);
      throw new RuntimeException("Report generation failed", e);
    } finally {
      document.close();
    }
  }

  // ══════════════════════════════════════════════════════════════════════════
  // Section: Cover
  // ══════════════════════════════════════════════════════════════════════════

  private void addCover(Document doc, FileEntity file) throws Exception {
    Font appF = new Font(Font.HELVETICA, 11, Font.BOLD, new Color(100, 116, 139));
    Font titleF = new Font(Font.HELVETICA, 24, Font.BOLD, C_HEADER_BG);
    Font subF = new Font(Font.HELVETICA, 13, Font.NORMAL, new Color(71, 85, 105));
    Font metaF = new Font(Font.HELVETICA, 10, Font.NORMAL, new Color(100, 116, 139));

    Paragraph app = centred(new Paragraph("TracePcap — Network Traffic Analysis Report", appF));
    app.setSpacingBefore(36);
    doc.add(app);

    Paragraph title = centred(new Paragraph(file.getFileName(), titleF));
    title.setSpacingBefore(8);
    doc.add(title);

    Paragraph gen =
        centred(new Paragraph("Report generated: " + LocalDateTime.now().format(DT_FMT), metaF));
    gen.setSpacingBefore(6);
    doc.add(gen);

    addDivider(doc);
  }

  // ══════════════════════════════════════════════════════════════════════════
  // Section: File Information
  // ══════════════════════════════════════════════════════════════════════════

  private void addFileInfo(Document doc, FileEntity file, int sec) throws Exception {
    addSectionHeader(doc, sec + ". File Information");

    String[][] rows = {
      {"File Name", file.getFileName()},
      {"File Size", formatBytes(file.getFileSize())},
      {"SHA-256 Hash", nvl(file.getFileHash())},
      {"Upload Time", formatDt(file.getUploadedAt())},
      {"Status", file.getStatus() != null ? file.getStatus().name() : "—"},
      {"nDPI Enrichment", file.isEnableNdpi() ? "Enabled" : "Disabled"},
      {"File Extraction", file.isEnableFileExtraction() ? "Enabled" : "Disabled"},
    };
    doc.add(kvTable(rows));
  }

  // ══════════════════════════════════════════════════════════════════════════
  // Section: Executive Summary
  // ══════════════════════════════════════════════════════════════════════════

  private void addExecutiveSummary(
      Document doc,
      FileEntity file,
      AnalysisResultEntity analysis,
      int hostCount,
      long totalConversations,
      long riskCount,
      int extractedCount,
      int countryCount,
      int sec)
      throws Exception {
    addSectionHeader(doc, sec + ". Executive Summary");

    String packets =
        analysis != null && analysis.getPacketCount() != null
            ? String.valueOf(analysis.getPacketCount())
            : "—";
    String totalBytes =
        analysis != null && analysis.getTotalBytes() != null
            ? formatBytes(analysis.getTotalBytes())
            : "—";
    String duration =
        analysis != null && analysis.getDurationMs() != null
            ? formatDuration(analysis.getDurationMs())
            : "—";
    String timeRange =
        analysis != null && analysis.getStartTime() != null && analysis.getEndTime() != null
            ? formatDt(analysis.getStartTime()) + "  →  " + formatDt(analysis.getEndTime())
            : "—";

    String[][] rows = {
      {"Total Packets", packets},
      {"Total Traffic Volume", totalBytes},
      {"Capture Duration", duration},
      {"Capture Time Range", timeRange},
      {"Total Conversations", String.valueOf(totalConversations)},
      {"At-Risk Conversations", String.valueOf(riskCount)},
      {"Unique Hosts Detected", String.valueOf(hostCount)},
      {"Countries Observed", String.valueOf(countryCount)},
      {"Extracted Files", String.valueOf(extractedCount)},
    };
    doc.add(kvTable(rows));
  }

  // ══════════════════════════════════════════════════════════════════════════
  // Section: Protocol Distribution
  // ══════════════════════════════════════════════════════════════════════════

  private void addProtocolDistribution(Document doc, Map<String, Object> protocolStats, int sec)
      throws Exception {
    addSectionHeader(doc, sec + ". Protocol Distribution");

    PdfPTable table = new PdfPTable(new float[] {3, 2, 2, 2});
    table.setWidthPercentage(100);
    table.setSpacingBefore(6);
    table.setSpacingAfter(12);
    addTableHeader(table, "Protocol", "Packets", "Bytes", "% Traffic");

    List<Map.Entry<String, Object>> sorted =
        protocolStats.entrySet().stream()
            .sorted(
                (a, b) ->
                    Long.compare(
                        getStatLong(b.getValue(), "packetCount"),
                        getStatLong(a.getValue(), "packetCount")))
            .toList();

    Font f = cellFont();
    for (int i = 0; i < sorted.size(); i++) {
      var e = sorted.get(i);
      Color bg = i % 2 == 0 ? Color.WHITE : C_ROW_ALT;
      addRow(
          table,
          bg,
          f,
          e.getKey(),
          String.valueOf(getStatLong(e.getValue(), "packetCount")),
          formatBytes(getStatLong(e.getValue(), "bytes")),
          String.format("%.1f%%", getStatDouble(e.getValue(), "percentage")));
    }
    doc.add(table);
  }

  // ══════════════════════════════════════════════════════════════════════════
  // Section: Category Distribution
  // ══════════════════════════════════════════════════════════════════════════

  private void addCategoryDistribution(Document doc, List<Object[]> categoryStats, int sec)
      throws Exception {
    addSectionHeader(doc, sec + ". Traffic Category Distribution");

    PdfPTable table = new PdfPTable(new float[] {4, 2});
    table.setWidthPercentage(100);
    table.setSpacingBefore(6);
    table.setSpacingAfter(12);
    addTableHeader(table, "Category", "Conversations");

    Font f = cellFont();
    for (int i = 0; i < categoryStats.size(); i++) {
      Object[] row = categoryStats.get(i);
      Color bg = i % 2 == 0 ? Color.WHITE : C_ROW_ALT;
      addRow(table, bg, f, nvl((String) row[0]), String.valueOf(((Number) row[1]).longValue()));
    }
    doc.add(table);
  }

  // ══════════════════════════════════════════════════════════════════════════
  // Section: Applications Detected
  // ══════════════════════════════════════════════════════════════════════════

  private void addApplicationsDetected(Document doc, List<Object[]> appStats, int sec)
      throws Exception {
    addSectionHeader(doc, sec + ". Applications Detected (" + appStats.size() + ")");

    PdfPTable table = new PdfPTable(new float[] {4, 2, 2});
    table.setWidthPercentage(100);
    table.setSpacingBefore(6);
    table.setSpacingAfter(12);
    addTableHeader(table, "Application", "Packets", "Bytes");

    Font f = cellFont();
    for (int i = 0; i < appStats.size(); i++) {
      Object[] row = appStats.get(i);
      Color bg = i % 2 == 0 ? Color.WHITE : C_ROW_ALT;
      addRow(
          table,
          bg,
          f,
          nvl((String) row[0]),
          String.valueOf(((Number) row[1]).longValue()),
          formatBytes(((Number) row[2]).longValue()));
    }
    doc.add(table);
  }

  // ══════════════════════════════════════════════════════════════════════════
  // Section: L7 Protocols
  // ══════════════════════════════════════════════════════════════════════════

  private void addL7Protocols(Document doc, List<Object[]> l7Stats, int sec) throws Exception {
    addSectionHeader(doc, sec + ". Detected L7 Protocols (" + l7Stats.size() + ")");

    PdfPTable table = new PdfPTable(new float[] {4, 2, 2});
    table.setWidthPercentage(100);
    table.setSpacingBefore(6);
    table.setSpacingAfter(12);
    addTableHeader(table, "L7 Protocol", "Packets", "Bytes");

    Font f = cellFont();
    for (int i = 0; i < l7Stats.size(); i++) {
      Object[] row = l7Stats.get(i);
      Color bg = i % 2 == 0 ? Color.WHITE : C_ROW_ALT;
      addRow(
          table,
          bg,
          f,
          nvl((String) row[0]),
          String.valueOf(((Number) row[1]).longValue()),
          formatBytes(((Number) row[2]).longValue()));
    }
    doc.add(table);
  }

  // ══════════════════════════════════════════════════════════════════════════
  // Section: Host Inventory (with supporting evidence)
  // ══════════════════════════════════════════════════════════════════════════

  private void addHostInventory(Document doc, List<HostClassificationEntity> hosts, int sec)
      throws Exception {
    addSectionHeader(doc, sec + ". Host Inventory (" + hosts.size() + " hosts)");

    PdfPTable table = new PdfPTable(new float[] {3, 3, 3, 2, 2, 1, 4});
    table.setWidthPercentage(100);
    table.setSpacingBefore(6);
    table.setSpacingAfter(12);
    addTableHeader(
        table,
        "IP Address",
        "MAC Address",
        "Manufacturer",
        "Device Type",
        "TTL Fingerprint",
        "Conf.",
        "Classification Evidence");

    Font f = cellFont();
    for (int i = 0; i < hosts.size(); i++) {
      HostClassificationEntity h = hosts.get(i);
      Color bg = i % 2 == 0 ? Color.WHITE : C_ROW_ALT;
      addRow(
          table,
          bg,
          f,
          nvl(h.getIp()),
          nvl(h.getMac()),
          nvl(h.getManufacturer()),
          nvl(h.getDeviceType()),
          ttlFingerprint(h.getTtl()),
          h.getConfidence() + "%",
          buildHostEvidence(h));
    }
    doc.add(table);

    // Legend
    Font legendFont = new Font(Font.HELVETICA, 8, Font.ITALIC, new Color(100, 116, 139));
    Paragraph legend =
        new Paragraph(
            "Evidence signals: MAC OUI vendor lookup · TTL OS fingerprint (64=Linux/Android/iOS,"
                + " 128=Windows, 255=Network device) · nDPI application profile · Traffic pattern"
                + " analysis (peer count, port behaviour, initiation ratio). Confidence reflects the"
                + " margin between the winning classification score and the second-best score.",
            legendFont);
    legend.setSpacingBefore(2);
    legend.setSpacingAfter(10);
    doc.add(legend);
  }

  private String ttlFingerprint(Integer ttl) {
    if (ttl == null) return "—";
    if (ttl > 128) return "TTL " + ttl + " → Network device";
    if (ttl > 64) return "TTL " + ttl + " → Windows";
    return "TTL " + ttl + " → Linux/Unix/iOS";
  }

  private String buildHostEvidence(HostClassificationEntity h) {
    StringBuilder sb = new StringBuilder();

    if (h.getManufacturer() != null) {
      sb.append("MAC vendor: ").append(h.getManufacturer());
      String hint = vendorDeviceHint(h.getManufacturer());
      if (hint != null) sb.append(" (→ ").append(hint).append(")");
    } else if (h.getMac() != null) {
      sb.append("MAC present, vendor unknown");
    } else {
      sb.append("No MAC data");
    }

    if (h.getTtl() != null) {
      sb.append("; TTL ").append(h.getTtl()).append(" → ").append(ttlOs(h.getTtl()));
    }

    if (h.getConfidence() == 100) {
      sb.append("; YAML rule override (confidence 100%)");
    }
    return sb.toString();
  }

  private String vendorDeviceHint(String manufacturer) {
    if (manufacturer == null) return null;
    String lower = manufacturer.toLowerCase();
    if (lower.contains("apple") || lower.contains("samsung") || lower.contains("xiaomi"))
      return "MOBILE";
    if (lower.contains("cisco")
        || lower.contains("huawei")
        || lower.contains("tp-link")
        || lower.contains("netgear")
        || lower.contains("ubiquiti")) return "ROUTER";
    if (lower.contains("dell")
        || lower.contains("intel")
        || lower.contains("lenovo")
        || lower.contains("hewlett")
        || lower.contains("hp inc")
        || lower.contains("acer")) return "LAPTOP_DESKTOP";
    if (lower.contains("raspberry") || lower.contains("espressif") || lower.contains("arduino"))
      return "IOT";
    return null;
  }

  private String ttlOs(Integer ttl) {
    if (ttl == null) return "unknown";
    if (ttl > 128) return "network device";
    if (ttl > 64) return "Windows";
    return "Linux/Unix/iOS/Android";
  }

  // ══════════════════════════════════════════════════════════════════════════
  // Section: Geo Summary
  // ══════════════════════════════════════════════════════════════════════════

  private void addGeoSummary(Document doc, List<Object[]> geoCountries, int sec) throws Exception {
    addSectionHeader(
        doc, sec + ". Geographic Distribution (" + geoCountries.size() + " countries)");

    PdfPTable table = new PdfPTable(new float[] {2, 5});
    table.setWidthPercentage(60);
    table.setHorizontalAlignment(Element.ALIGN_LEFT);
    table.setSpacingBefore(6);
    table.setSpacingAfter(12);
    addTableHeader(table, "Country Code", "Country");

    Font f = cellFont();
    for (int i = 0; i < geoCountries.size(); i++) {
      Object[] row = geoCountries.get(i);
      Color bg = i % 2 == 0 ? Color.WHITE : C_ROW_ALT;
      addRow(table, bg, f, nvl((String) row[0]), nvl((String) row[1]));
    }
    doc.add(table);
  }

  // ══════════════════════════════════════════════════════════════════════════
  // Section: Risk Type Summary
  // ══════════════════════════════════════════════════════════════════════════

  private void addRiskTypeSummary(
      Document doc, List<String> riskTypes, List<String> customSigs, int sec) throws Exception {
    addSectionHeader(doc, sec + ". Risk & Signature Summary");

    if (!riskTypes.isEmpty()) {
      addSubHeader(doc, "nDPI Flow Risk Types Detected");
      PdfPTable t = tagTable(riskTypes);
      doc.add(t);
    }

    if (!customSigs.isEmpty()) {
      addSubHeader(doc, "Custom Signature Rules Triggered");
      PdfPTable t = tagTable(customSigs);
      doc.add(t);
    }
  }

  private PdfPTable tagTable(List<String> items) {
    PdfPTable table = new PdfPTable(1);
    table.setWidthPercentage(100);
    table.setSpacingBefore(4);
    table.setSpacingAfter(10);
    Font f = cellFont();
    for (int i = 0; i < items.size(); i++) {
      PdfPCell cell = new PdfPCell(new Phrase("• " + items.get(i), f));
      cell.setBackgroundColor(i % 2 == 0 ? Color.WHITE : C_ROW_ALT);
      cell.setPadding(5);
      cell.setBorderColor(new Color(226, 232, 240));
      table.addCell(cell);
    }
    return table;
  }

  // ══════════════════════════════════════════════════════════════════════════
  // Section: Security Findings
  // ══════════════════════════════════════════════════════════════════════════

  private void addSecurityFindings(Document doc, List<ConversationEntity> risky, int sec)
      throws Exception {
    addSectionHeader(doc, sec + ". Security Findings (" + risky.size() + " at-risk conversations)");

    PdfPTable table = new PdfPTable(new float[] {3, 3, 2, 2, 2, 5});
    table.setWidthPercentage(100);
    table.setSpacingBefore(6);
    table.setSpacingAfter(12);
    addTableHeader(
        table, "Source", "Destination", "Protocol", "Application", "Bytes", "Risk Flags");

    Font f = cellFont();
    for (ConversationEntity c : risky) {
      String src = endpoint(c.getSrcIp(), c.getSrcPort());
      String dst = endpoint(c.getDstIp(), c.getDstPort());
      String risks = joinRisks(c.getFlowRisks(), c.getCustomSignatures());
      addRow(
          table,
          C_RISK_BG,
          f,
          src,
          dst,
          nvl(c.getProtocol()),
          nvl(c.getAppName()),
          c.getTotalBytes() != null ? formatBytes(c.getTotalBytes()) : "—",
          risks);
    }
    doc.add(table);
  }

  // ══════════════════════════════════════════════════════════════════════════
  // Section: TLS Analysis
  // ══════════════════════════════════════════════════════════════════════════

  private void addTlsAnalysis(Document doc, List<ConversationEntity> tlsConvs, int sec)
      throws Exception {
    addSectionHeader(
        doc, sec + ". TLS / HTTPS Analysis (" + tlsConvs.size() + " encrypted conversations)");

    PdfPTable table = new PdfPTable(new float[] {3, 3, 3, 3, 3, 4, 3, 3});
    table.setWidthPercentage(100);
    table.setSpacingBefore(6);
    table.setSpacingAfter(12);
    addTableHeader(
        table,
        "Source",
        "Destination",
        "Hostname (SNI)",
        "JA3 Client",
        "JA3 Server",
        "Subject (CN)",
        "Valid From",
        "Valid To");

    Font f = new Font(Font.HELVETICA, 7, Font.NORMAL, C_TEXT);
    for (int i = 0; i < tlsConvs.size(); i++) {
      ConversationEntity c = tlsConvs.get(i);
      Color bg = i % 2 == 0 ? Color.WHITE : C_ROW_ALT;
      addRow(
          table,
          bg,
          f,
          endpoint(c.getSrcIp(), c.getSrcPort()),
          endpoint(c.getDstIp(), c.getDstPort()),
          nvl(c.getHostname()),
          truncate(c.getJa3Client(), 10),
          truncate(c.getJa3Server(), 10),
          truncate(c.getTlsSubject(), 30),
          formatDt(c.getTlsNotBefore()),
          formatDt(c.getTlsNotAfter()));
    }
    doc.add(table);
  }

  // ══════════════════════════════════════════════════════════════════════════
  // Section: HTTP User Agents
  // ══════════════════════════════════════════════════════════════════════════

  private void addHttpUserAgents(Document doc, List<String> agents, int sec) throws Exception {
    addSectionHeader(doc, sec + ". HTTP User Agents (" + agents.size() + " distinct)");
    doc.add(tagTable(agents));
  }

  // ══════════════════════════════════════════════════════════════════════════
  // Section: Top Conversations
  // ══════════════════════════════════════════════════════════════════════════

  private void addTopConversations(Document doc, List<ConversationEntity> convs, int sec)
      throws Exception {
    addSectionHeader(doc, sec + ". Top Conversations by Traffic (top " + convs.size() + ")");

    PdfPTable table = new PdfPTable(new float[] {3, 3, 2, 3, 3, 2, 2, 2});
    table.setWidthPercentage(100);
    table.setSpacingBefore(6);
    table.setSpacingAfter(12);
    addTableHeader(
        table,
        "Source",
        "Destination",
        "Protocol",
        "Application",
        "Hostname",
        "Packets",
        "Bytes",
        "Duration");

    Font f = cellFont();
    for (int i = 0; i < convs.size(); i++) {
      ConversationEntity c = convs.get(i);
      Color bg = i % 2 == 0 ? Color.WHITE : C_ROW_ALT;
      long ms =
          (c.getStartTime() != null && c.getEndTime() != null)
              ? java.time.Duration.between(c.getStartTime(), c.getEndTime()).toMillis()
              : 0;
      addRow(
          table,
          bg,
          f,
          endpoint(c.getSrcIp(), c.getSrcPort()),
          endpoint(c.getDstIp(), c.getDstPort()),
          nvl(c.getProtocol()),
          nvl(c.getAppName()),
          nvl(c.getHostname()),
          c.getPacketCount() != null ? String.valueOf(c.getPacketCount()) : "—",
          c.getTotalBytes() != null ? formatBytes(c.getTotalBytes()) : "—",
          formatDuration(ms));
    }
    doc.add(table);
  }

  // ══════════════════════════════════════════════════════════════════════════
  // Section: Detected File Types
  // ══════════════════════════════════════════════════════════════════════════

  private void addDetectedFileTypes(Document doc, List<String> fileTypes, int sec)
      throws Exception {
    addSectionHeader(
        doc, sec + ". Detected File Types in Packet Payloads (" + fileTypes.size() + ")");
    doc.add(tagTable(fileTypes));
  }

  // ══════════════════════════════════════════════════════════════════════════
  // Section: Extracted Files
  // ══════════════════════════════════════════════════════════════════════════

  private void addExtractedFiles(Document doc, List<ExtractedFileEntity> files, int sec)
      throws Exception {
    addSectionHeader(doc, sec + ". Extracted Files (" + files.size() + ")");

    PdfPTable table = new PdfPTable(new float[] {4, 3, 2, 2, 7});
    table.setWidthPercentage(100);
    table.setSpacingBefore(6);
    table.setSpacingAfter(12);
    addTableHeader(table, "Filename", "MIME Type", "Size", "Method", "SHA-256");

    Font f = new Font(Font.HELVETICA, 8, Font.NORMAL, C_TEXT);
    for (int i = 0; i < files.size(); i++) {
      ExtractedFileEntity ef = files.get(i);
      Color bg = i % 2 == 0 ? Color.WHITE : C_ROW_ALT;
      addRow(
          table,
          bg,
          f,
          nvl(ef.getFilename()),
          nvl(ef.getMimeType()),
          ef.getFileSize() != null ? formatBytes(ef.getFileSize()) : "—",
          nvl(ef.getExtractionMethod()),
          nvl(ef.getSha256()));
    }
    doc.add(table);
  }

  // ══════════════════════════════════════════════════════════════════════════
  // Section: Network Topology Diagrams (frontend-rendered PNG)
  // ══════════════════════════════════════════════════════════════════════════

  private void addTopologyDiagram(
      Document doc, String base64Image, String layoutName, int sectionNum) throws Exception {

    // Each topology diagram gets its own full landscape page.
    // Use an explicit Rectangle rather than rotate() so the size is applied
    // unambiguously regardless of the previous page's orientation.
    Rectangle landscape = new Rectangle(PageSize.A4.getHeight(), PageSize.A4.getWidth());
    doc.setPageSize(landscape);
    doc.newPage();

    // Compact title — avoids the ~50pt overhead of the banner-style section
    // header so the image fits on the same page without shrinking.
    Font titleFont = new Font(Font.HELVETICA, 11, Font.BOLD, C_HEADER_BG);
    Paragraph title = new Paragraph(sectionNum + ". Network Topology — " + layoutName, titleFont);
    title.setSpacingBefore(4);
    title.setSpacingAfter(6);
    doc.add(title);

    if (base64Image == null || base64Image.isBlank()) {
      doc.add(new Paragraph("Diagram image not provided.", cellFont()));
      return;
    }

    // Usable area: landscape height minus top+bottom margins (100), title (21),
    // image spacingBefore (8), and disclaimer with its spacing (40).
    float usableW = landscape.getWidth() - 80f;
    float usableH = landscape.getHeight() - 100f - 21f - 8f - 40f;

    byte[] imageBytes;
    try {
      String data = base64Image.contains(",") ? base64Image.split(",")[1] : base64Image;
      imageBytes = Base64.getDecoder().decode(data);
    } catch (IllegalArgumentException e) {
      log.warn("Invalid base64 image data for layout: {}", layoutName);
      doc.add(new Paragraph("Invalid diagram image data.", cellFont()));
      return;
    }
    Image img = Image.getInstance(imageBytes);
    img.scaleToFit(usableW, usableH);
    img.setAlignment(Image.ALIGN_CENTER);
    img.setSpacingBefore(8);
    doc.add(img);

    Font disclaimerFont = new Font(Font.HELVETICA, 7.5f, Font.ITALIC, new Color(120, 120, 120));
    Paragraph disclaimer =
        new Paragraph(
            "Note: This diagram is automatically generated and may not render all connections accurately for large or complex network captures. "
                + "For a complete view, consider taking a manual screenshot from the Network Diagram page.",
            disclaimerFont);
    disclaimer.setAlignment(Element.ALIGN_CENTER);
    disclaimer.setSpacingBefore(6);
    doc.add(disclaimer);
  }

  // ══════════════════════════════════════════════════════════════════════════
  // PDF building helpers
  // ══════════════════════════════════════════════════════════════════════════

  private void addSectionHeader(Document doc, String title) throws Exception {
    Font font = new Font(Font.HELVETICA, 12, Font.BOLD, Color.WHITE);
    PdfPTable banner = new PdfPTable(1);
    banner.setWidthPercentage(100);
    banner.setSpacingBefore(18);
    banner.setSpacingAfter(2);
    PdfPCell cell = new PdfPCell(new Phrase(title, font));
    cell.setBackgroundColor(C_HEADER_BG);
    cell.setPadding(8);
    cell.setBorder(Rectangle.NO_BORDER);
    banner.addCell(cell);
    doc.add(banner);
  }

  private void addSubHeader(Document doc, String title) throws Exception {
    Font font = new Font(Font.HELVETICA, 10, Font.BOLD, Color.WHITE);
    PdfPTable banner = new PdfPTable(1);
    banner.setWidthPercentage(100);
    banner.setSpacingBefore(8);
    banner.setSpacingAfter(2);
    PdfPCell cell = new PdfPCell(new Phrase(title, font));
    cell.setBackgroundColor(C_SUBHEADER_BG);
    cell.setPadding(6);
    cell.setBorder(Rectangle.NO_BORDER);
    banner.addCell(cell);
    doc.add(banner);
  }

  private void addDivider(Document doc) throws Exception {
    PdfPTable line = new PdfPTable(1);
    line.setWidthPercentage(100);
    line.setSpacingBefore(16);
    line.setSpacingAfter(16);
    PdfPCell cell = new PdfPCell(new Phrase(" "));
    cell.setBackgroundColor(C_DIVIDER);
    cell.setBorder(Rectangle.NO_BORDER);
    cell.setFixedHeight(2f);
    line.addCell(cell);
    doc.add(line);
  }

  private void addTableHeader(PdfPTable table, String... headers) {
    Font font = new Font(Font.HELVETICA, 9, Font.BOLD, Color.WHITE);
    for (String h : headers) {
      PdfPCell cell = new PdfPCell(new Phrase(h, font));
      cell.setBackgroundColor(C_SUBHEADER_BG);
      cell.setPadding(6);
      cell.setHorizontalAlignment(Element.ALIGN_LEFT);
      cell.setBorderColor(C_DIVIDER);
      table.addCell(cell);
    }
  }

  private void addRow(PdfPTable table, Color bg, Font font, String... values) {
    for (String v : values) {
      PdfPCell cell = new PdfPCell(new Phrase(nvl(v), font));
      cell.setBackgroundColor(bg);
      cell.setPadding(5);
      cell.setBorderColor(new Color(226, 232, 240));
      table.addCell(cell);
    }
  }

  /** Two-column key → value table used for metadata sections. */
  private PdfPTable kvTable(String[][] rows) {
    PdfPTable table = new PdfPTable(new float[] {2, 5});
    table.setWidthPercentage(100);
    table.setSpacingBefore(6);
    table.setSpacingAfter(12);
    Font labelFont = new Font(Font.HELVETICA, 10, Font.BOLD, C_LABEL);
    Font valueFont = new Font(Font.HELVETICA, 10, Font.NORMAL, C_TEXT);
    for (int i = 0; i < rows.length; i++) {
      Color bg = i % 2 == 0 ? Color.WHITE : C_ROW_ALT;
      PdfPCell lc = new PdfPCell(new Phrase(rows[i][0], labelFont));
      lc.setBackgroundColor(bg);
      lc.setPadding(6);
      lc.setBorder(Rectangle.NO_BORDER);
      table.addCell(lc);
      PdfPCell vc = new PdfPCell(new Phrase(rows[i][1], valueFont));
      vc.setBackgroundColor(bg);
      vc.setPadding(6);
      vc.setBorder(Rectangle.NO_BORDER);
      table.addCell(vc);
    }
    return table;
  }

  private static Paragraph centred(Paragraph p) {
    p.setAlignment(Element.ALIGN_CENTER);
    return p;
  }

  private static Font cellFont() {
    return new Font(Font.HELVETICA, 9, Font.NORMAL, new Color(30, 41, 59));
  }

  // ══════════════════════════════════════════════════════════════════════════
  // Formatters
  // ══════════════════════════════════════════════════════════════════════════

  private static String formatBytes(Long bytes) {
    if (bytes == null) return "—";
    if (bytes < 1_024) return bytes + " B";
    if (bytes < 1_048_576) return String.format("%.1f KB", bytes / 1_024.0);
    if (bytes < 1_073_741_824) return String.format("%.1f MB", bytes / 1_048_576.0);
    return String.format("%.2f GB", bytes / 1_073_741_824.0);
  }

  private static String formatBytes(long bytes) {
    return formatBytes((Long) bytes);
  }

  private static String formatDuration(long ms) {
    if (ms <= 0) return "—";
    long s = ms / 1_000;
    long h = s / 3_600;
    long m = (s % 3_600) / 60;
    long sec = s % 60;
    if (h > 0) return String.format("%dh %02dm %02ds", h, m, sec);
    if (m > 0) return String.format("%dm %02ds", m, sec);
    return String.format("%ds", sec);
  }

  private static String formatDt(LocalDateTime dt) {
    return dt != null ? dt.format(DT_FMT) : "—";
  }

  private static String nvl(String s) {
    return (s != null && !s.isBlank()) ? s : "—";
  }

  private static String endpoint(String ip, Integer port) {
    if (ip == null) return "—";
    return port != null ? ip + ":" + port : ip;
  }

  private static String truncate(String s, int maxLen) {
    if (s == null || s.isBlank()) return "—";
    return s.length() > maxLen ? s.substring(0, maxLen) + "…" : s;
  }

  private static String abbreviate(String s, int maxLen) {
    if (s == null) return "";
    return s.length() > maxLen ? s.substring(0, maxLen - 1) + "…" : s;
  }

  private static String joinRisks(String[] flowRisks, String[] customSigs) {
    StringBuilder sb = new StringBuilder();
    if (flowRisks != null) {
      for (String r : flowRisks) sb.append(r).append(" ");
    }
    if (customSigs != null) {
      for (String s : customSigs) sb.append("[SIG] ").append(s).append(" ");
    }
    String result = sb.toString().trim();
    return result.isBlank() ? "—" : result;
  }

  // ══════════════════════════════════════════════════════════════════════════
  // protocolStats helpers
  // ══════════════════════════════════════════════════════════════════════════

  private static long getStatLong(Object stat, String key) {
    if (stat instanceof Map<?, ?> m) {
      Object v = m.get(key);
      if (v instanceof Number n) return n.longValue();
    }
    return 0L;
  }

  private static double getStatDouble(Object stat, String key) {
    if (stat instanceof Map<?, ?> m) {
      Object v = m.get(key);
      if (v instanceof Number n) return n.doubleValue();
    }
    return 0.0;
  }
}
