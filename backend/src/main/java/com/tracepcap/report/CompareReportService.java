package com.tracepcap.report;

import com.lowagie.text.Document;
import com.lowagie.text.Element;
import com.lowagie.text.Font;
import com.lowagie.text.Image;
import com.lowagie.text.PageSize;
import com.lowagie.text.Paragraph;
import com.lowagie.text.Phrase;
import com.lowagie.text.Rectangle;
import com.lowagie.text.pdf.ColumnText;
import com.lowagie.text.pdf.PdfContentByte;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfWriter;
import com.tracepcap.analysis.entity.ConversationEntity;
import com.tracepcap.analysis.entity.HostClassificationEntity;
import com.tracepcap.analysis.repository.AnalysisResultRepository;
import com.tracepcap.analysis.repository.ConversationRepository;
import com.tracepcap.analysis.repository.HostClassificationRepository;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.repository.FileRepository;
import java.awt.Color;
import java.io.OutputStream;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class CompareReportService {

  private static final int SECURITY_FINDINGS_LIMIT = 50;

  // ── PDF colours (shared palette with ReportService) ───────────────────────
  private static final Color C_HEADER_BG  = new Color(30,  64, 175);
  private static final Color C_SUBHDR_BG  = new Color(59, 130, 246);
  private static final Color C_ROW_ALT    = new Color(239, 246, 255);
  private static final Color C_DIVIDER    = new Color(147, 197, 253);
  private static final Color C_TEXT       = new Color(30,  41,  59);
  private static final Color C_LABEL      = new Color(30,  41,  59);
  private static final Color C_RISK_BG    = new Color(254, 226, 226);

  private static final DateTimeFormatter DT_FMT =
      DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss");

  private final FileRepository fileRepository;
  private final AnalysisResultRepository analysisResultRepository;
  private final ConversationRepository conversationRepository;
  private final HostClassificationRepository hostClassificationRepository;

  // ══════════════════════════════════════════════════════════════════════════
  // Public entry point
  // ══════════════════════════════════════════════════════════════════════════

  @Transactional(readOnly = true)
  public void generateReport(CompareReportRequest request, OutputStream out) {
    if (request.getFileIds() == null || request.getFileIds().size() < 2) {
      throw new IllegalArgumentException("At least two file IDs are required for a compare report");
    }

    List<UUID> fileIds     = request.getFileIds();
    List<String> labels    = request.getFileLabels();

    List<FileEntity> files = fileIds.stream()
        .map(id -> fileRepository.findById(id)
            .orElseThrow(() -> new IllegalArgumentException("File not found: " + id)))
        .toList();

    Document document = new Document(PageSize.A4, 40, 40, 60, 40);
    try {
      PdfWriter writer = PdfWriter.getInstance(document, out);
      document.open();

      int sec = 1;
      addCover(document, files, labels);
      addComparisonOverview(document, fileIds, labels, sec++);

      // Combined security findings across all files
      List<ConversationEntity> allRisky = fileIds.stream()
          .flatMap(id -> conversationRepository
              .findAtRiskByFileIdLimited(id, SECURITY_FINDINGS_LIMIT).stream())
          .sorted((a, b) -> {
            int ra = a.getFlowRisks() != null ? a.getFlowRisks().length : 0;
            int rb = b.getFlowRisks() != null ? b.getFlowRisks().length : 0;
            if (rb != ra) return Integer.compare(rb, ra);
            long ba = a.getTotalBytes() != null ? a.getTotalBytes() : 0;
            long bb = b.getTotalBytes() != null ? b.getTotalBytes() : 0;
            return Long.compare(bb, ba);
          })
          .limit(SECURITY_FINDINGS_LIMIT)
          .toList();

      if (!allRisky.isEmpty()) {
        addSecurityFindings(document, allRisky, fileIds, labels, sec++);
      }

      List<String> activeFilters =
          request.getActiveFilters() != null ? request.getActiveFilters() : List.of();
      String nodeLimitNote = request.getNodeLimitNote();
      addTopologyDiagram(
          document, writer, request.getForceDirectedImage(), "Force-Directed Layout", sec++,
          activeFilters, nodeLimitNote);
      addTopologyDiagram(
          document, writer, request.getHierarchicalImage(), "Hierarchical Layout (Top-Down)", sec,
          activeFilters, nodeLimitNote);

    } catch (Exception e) {
      log.error("Compare PDF generation failed", e);
      throw new RuntimeException("Compare report generation failed", e);
    } finally {
      document.close();
    }
  }

  // ══════════════════════════════════════════════════════════════════════════
  // Section: Cover
  // ══════════════════════════════════════════════════════════════════════════

  private void addCover(Document doc, List<FileEntity> files, List<String> labels)
      throws Exception {
    Font appF   = new Font(Font.HELVETICA, 11, Font.BOLD,   new Color(100, 116, 139));
    Font titleF = new Font(Font.HELVETICA, 22, Font.BOLD,   C_HEADER_BG);
    Font subF   = new Font(Font.HELVETICA, 11, Font.NORMAL, new Color(71, 85, 105));
    Font metaF  = new Font(Font.HELVETICA, 10, Font.NORMAL, new Color(100, 116, 139));

    Paragraph app = centred(new Paragraph("TracePcap — Compare Network Topology Report", appF));
    app.setSpacingBefore(36);
    doc.add(app);

    Paragraph title = centred(new Paragraph("Multi-File Topology Comparison", titleF));
    title.setSpacingBefore(8);
    doc.add(title);

    Paragraph gen = centred(
        new Paragraph("Report generated: " + LocalDateTime.now().format(DT_FMT), metaF));
    gen.setSpacingBefore(6);
    doc.add(gen);

    addDivider(doc);

    Font fileF = new Font(Font.HELVETICA, 10, Font.NORMAL, C_TEXT);
    for (int i = 0; i < files.size(); i++) {
      String label = (labels != null && i < labels.size()) ? labels.get(i) : files.get(i).getFileName();
      Paragraph p = centred(new Paragraph((i + 1) + ". " + label, fileF));
      p.setSpacingBefore(4);
      doc.add(p);
    }
  }

  // ══════════════════════════════════════════════════════════════════════════
  // Section: Comparison Overview
  // ══════════════════════════════════════════════════════════════════════════

  private void addComparisonOverview(Document doc, List<UUID> fileIds, List<String> labels, int sec)
      throws Exception {
    addSectionHeader(doc, sec + ". Comparison Overview");

    PdfPTable table = new PdfPTable(new float[]{4, 2, 2, 2, 2, 2, 2});
    table.setWidthPercentage(100);
    table.setSpacingBefore(6);
    table.setSpacingAfter(12);
    addTableHeader(table, "File", "Conversations", "At Risk", "Hosts", "Packets", "Data", "Risk %");

    Font f = cellFont();
    for (int i = 0; i < fileIds.size(); i++) {
      UUID id    = fileIds.get(i);
      String lbl = (labels != null && i < labels.size()) ? labels.get(i) : id.toString();

      long totalConvs = conversationRepository.countByFileId(id);
      long riskCount  = conversationRepository.countAtRiskByFileId(id);
      long hostCount  = hostClassificationRepository.countByFileId(id);

      var analysis = analysisResultRepository.findByFileId(id).orElse(null);
      String packets  = analysis != null && analysis.getPacketCount() != null
          ? String.valueOf(analysis.getPacketCount()) : "—";
      String data     = analysis != null && analysis.getTotalBytes() != null
          ? formatBytes(analysis.getTotalBytes()) : "—";
      String riskPct  = totalConvs > 0
          ? String.format("%.1f%%", riskCount * 100.0 / totalConvs) : "—";

      Color bg = i % 2 == 0 ? Color.WHITE : C_ROW_ALT;
      addRow(table, bg, f,
          lbl,
          String.valueOf(totalConvs),
          String.valueOf(riskCount),
          String.valueOf(hostCount),
          packets,
          data,
          riskPct);
    }
    doc.add(table);
  }

  // ══════════════════════════════════════════════════════════════════════════
  // Section: Combined Security Findings
  // ══════════════════════════════════════════════════════════════════════════

  private void addSecurityFindings(
      Document doc,
      List<ConversationEntity> convs,
      List<UUID> fileIds,
      List<String> labels,
      int sec)
      throws Exception {
    addSectionHeader(doc, sec + ". Security Findings (" + convs.size() + " at-risk conversations)");

    PdfPTable table = new PdfPTable(new float[]{2, 3, 3, 2, 3, 2, 5});
    table.setWidthPercentage(100);
    table.setSpacingBefore(6);
    table.setSpacingAfter(12);
    addTableHeader(table, "Source File", "Source", "Destination", "Protocol", "Application", "Bytes", "Risks");

    Font f = cellFont();
    for (int i = 0; i < convs.size(); i++) {
      ConversationEntity c = convs.get(i);
      Color bg = c.getFlowRisks() != null && c.getFlowRisks().length > 0 ? C_RISK_BG
          : (i % 2 == 0 ? Color.WHITE : C_ROW_ALT);

      // Resolve which file label this conversation belongs to
      String fileLabel = "—";
      if (c.getFile() != null) {
        UUID cFileId = c.getFile().getId();
        int idx = fileIds.indexOf(cFileId);
        if (idx >= 0 && labels != null && idx < labels.size()) {
          fileLabel = labels.get(idx);
        }
      }

      String risks = c.getFlowRisks() != null ? String.join(", ", c.getFlowRisks()) : "—";
      addRow(table, bg, f,
          fileLabel,
          endpoint(c.getSrcIp(), c.getSrcPort()),
          endpoint(c.getDstIp(), c.getDstPort()),
          nvl(c.getProtocol()),
          nvl(c.getAppName()),
          c.getTotalBytes() != null ? formatBytes(c.getTotalBytes()) : "—",
          risks.isBlank() ? "—" : risks);
    }
    doc.add(table);
  }

  // ══════════════════════════════════════════════════════════════════════════
  // Section: Network Topology Diagram
  // ══════════════════════════════════════════════════════════════════════════

  private void addTopologyDiagram(
      Document doc, PdfWriter writer, String base64Image, String layoutName, int sectionNum,
      List<String> activeFilters, String nodeLimitNote)
      throws Exception {

    float pageW = PageSize.A4.getHeight();
    float pageH = PageSize.A4.getWidth();
    doc.setPageSize(new Rectangle(pageW, pageH));
    doc.setMargins(40, 40, 40, 40);
    doc.newPage();
    if (writer.getPageSize().getHeight() >= writer.getPageSize().getWidth()
        && writer.getPageSize().getWidth() < pageW - 1f) {
      doc.newPage();
    }

    final int   BADGE_COLS  = 5;
    final float MARGIN      = 40f;
    final float TITLE_H     = 16f;
    final float TITLE_GAP   = 6f;
    final float FOOTER_GAP  = 8f;

    List<String> nonNullFilters = (activeFilters != null)
        ? activeFilters.stream().filter(f -> f != null)
            .collect(java.util.stream.Collectors.toList())
        : List.of();
    boolean hasFilters  = !nonNullFilters.isEmpty();
    boolean hasNodeNote = nodeLimitNote != null && !nodeLimitNote.isBlank();

    float contentW = pageW - MARGIN * 2;

    Font disclaimerFont = new Font(Font.HELVETICA, 7.5f, Font.ITALIC, new Color(120, 120, 120));
    Font noteFont       = new Font(Font.HELVETICA, 7.5f, Font.ITALIC, new Color(80,  80,  80));

    PdfPTable badges  = null;
    float badgesH = 0f;
    if (hasFilters) {
      Font labelFont = new Font(Font.HELVETICA, 7f, Font.BOLD,   new Color(30,  64, 175));
      Font valueFont = new Font(Font.HELVETICA, 7f, Font.NORMAL, new Color(30,  41,  59));
      Color chipBg   = new Color(219, 234, 254);
      int cols = Math.min(nonNullFilters.size(), BADGE_COLS);
      badges = new PdfPTable(cols);
      badges.setTotalWidth(contentW);
      for (String filter : nonNullFilters) {
        int colon = filter.indexOf(':');
        Phrase phrase = new Phrase();
        if (colon > 0) {
          phrase.add(new Phrase(filter.substring(0, colon + 1) + " ", labelFont));
          phrase.add(new Phrase(filter.substring(colon + 1).trim(), valueFont));
        } else {
          phrase.add(new Phrase(filter, valueFont));
        }
        PdfPCell chip = new PdfPCell(phrase);
        chip.setBackgroundColor(chipBg);
        chip.setPaddingTop(2); chip.setPaddingBottom(2);
        chip.setPaddingLeft(5); chip.setPaddingRight(5);
        chip.setBorderColor(new Color(147, 197, 253));
        chip.setBorderWidth(0.5f);
        badges.addCell(chip);
      }
      int remainder = nonNullFilters.size() % cols;
      if (remainder != 0) {
        for (int p = remainder; p < cols; p++) {
          PdfPCell empty = new PdfPCell(new Phrase(""));
          empty.setBorder(Rectangle.NO_BORDER);
          badges.addCell(empty);
        }
      }
      badgesH = badges.getTotalHeight();
    }

    PdfPTable textFooter = new PdfPTable(1);
    textFooter.setTotalWidth(contentW);
    if (hasNodeNote) {
      PdfPCell noteCell = new PdfPCell(new Phrase(nodeLimitNote, noteFont));
      noteCell.setBorder(Rectangle.NO_BORDER);
      noteCell.setHorizontalAlignment(Element.ALIGN_CENTER);
      noteCell.setPaddingTop(0); noteCell.setPaddingBottom(2);
      textFooter.addCell(noteCell);
    }
    PdfPCell discCell = new PdfPCell(new Phrase(
        "Note: This diagram is automatically generated and may not render all connections accurately "
            + "for large or complex network captures. For a complete view, consider taking a manual "
            + "screenshot from the Compare Topology page.",
        disclaimerFont));
    discCell.setBorder(Rectangle.NO_BORDER);
    discCell.setHorizontalAlignment(Element.ALIGN_CENTER);
    discCell.setPaddingTop(0); discCell.setPaddingBottom(0);
    textFooter.addCell(discCell);
    float textFooterH = textFooter.getTotalHeight();

    float footerH = FOOTER_GAP + textFooterH + badgesH;

    float titleTop = pageH - MARGIN;
    float imageTop = titleTop - TITLE_H - TITLE_GAP;
    float imageBot = MARGIN + footerH;
    float usableH  = imageTop - imageBot;

    PdfContentByte cb = writer.getDirectContent();
    Font titleFont = new Font(Font.HELVETICA, 11, Font.BOLD, C_HEADER_BG);
    ColumnText ctTitle = new ColumnText(cb);
    ctTitle.setSimpleColumn(MARGIN, titleTop - TITLE_H, MARGIN + contentW, titleTop);
    ctTitle.setAlignment(Element.ALIGN_LEFT);
    ctTitle.addText(new Phrase(sectionNum + ". Network Topology \u2014 " + layoutName, titleFont));
    ctTitle.go();

    if (base64Image == null || base64Image.isBlank()) {
      ColumnText ctErr = new ColumnText(cb);
      ctErr.setSimpleColumn(MARGIN, imageBot, MARGIN + contentW, imageTop);
      ctErr.addText(new Phrase("Diagram image not provided.", cellFont()));
      ctErr.go();
      doc.add(new Paragraph(" "));
      return;
    }

    byte[] imageBytes;
    try {
      String data = base64Image.contains(",") ? base64Image.split(",")[1] : base64Image;
      imageBytes = Base64.getDecoder().decode(data);
    } catch (IllegalArgumentException e) {
      log.warn("Invalid base64 image data for layout: {}", layoutName);
      ColumnText ctErr = new ColumnText(cb);
      ctErr.setSimpleColumn(MARGIN, imageBot, MARGIN + contentW, imageTop);
      ctErr.addText(new Phrase("Invalid diagram image data.", cellFont()));
      ctErr.go();
      doc.add(new Paragraph(" "));
      return;
    }
    Image img = Image.getInstance(imageBytes);
    img.scaleToFit(contentW, usableH);
    float imgX = MARGIN + (contentW - img.getScaledWidth()) / 2f;
    float imgY = imageTop - img.getScaledHeight();
    img.setAbsolutePosition(imgX, imgY);
    cb.addImage(img);

    float y = MARGIN;
    if (badges != null) {
      badges.writeSelectedRows(0, -1, MARGIN, y + badgesH, cb);
      y += badgesH;
    }
    y += FOOTER_GAP;
    textFooter.writeSelectedRows(0, -1, MARGIN, y + textFooterH, cb);

    doc.add(new Paragraph(" "));
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

  private void addTableHeader(PdfPTable table, String... headers) {
    Font font = new Font(Font.HELVETICA, 9, Font.BOLD, Color.WHITE);
    for (String h : headers) {
      PdfPCell cell = new PdfPCell(new Phrase(h, font));
      cell.setBackgroundColor(C_SUBHDR_BG);
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

  private static Paragraph centred(Paragraph p) {
    p.setAlignment(Element.ALIGN_CENTER);
    return p;
  }

  private static Font cellFont() {
    return new Font(Font.HELVETICA, 9, Font.NORMAL, C_TEXT);
  }

  private static String formatBytes(long bytes) {
    if (bytes < 1_024)         return bytes + " B";
    if (bytes < 1_048_576)     return String.format("%.1f KB", bytes / 1_024.0);
    if (bytes < 1_073_741_824) return String.format("%.1f MB", bytes / 1_048_576.0);
    return String.format("%.2f GB", bytes / 1_073_741_824.0);
  }

  private static String nvl(String s) {
    return (s != null && !s.isBlank()) ? s : "—";
  }

  private static String endpoint(String ip, Integer port) {
    if (ip == null) return "—";
    return port != null ? ip + ":" + port : ip;
  }
}
