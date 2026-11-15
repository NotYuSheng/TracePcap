package com.tracepcap.report;

import com.lowagie.text.Chunk;
import com.lowagie.text.Document;
import com.lowagie.text.Element;
import com.lowagie.text.Font;
import com.lowagie.text.Paragraph;
import com.lowagie.text.Phrase;
import com.lowagie.text.Rectangle;
import com.lowagie.text.pdf.BaseFont;
import com.lowagie.text.pdf.ColumnText;
import com.lowagie.text.pdf.PdfContentByte;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfPageEventHelper;
import com.lowagie.text.pdf.PdfTemplate;
import com.lowagie.text.pdf.PdfWriter;
import java.awt.Color;

/** The report's look: type, colours, headings, tables, and each page's running header and footer. */
final class ReportPdf {

  static final Color TEXT = new Color(31, 41, 55);
  static final Color MUTED = new Color(82, 90, 104);
  static final Color FAINT = new Color(122, 130, 145);
  static final Color ACCENT = new Color(59, 24, 145);
  static final Color ACCENT_BG = new Color(247, 245, 255);
  static final Color ACCENT_LINE = new Color(221, 214, 254);
  static final Color RULE = new Color(228, 231, 236);
  static final Color ROW_LINE = new Color(240, 241, 244);
  static final Color HIGH = new Color(180, 35, 24);
  static final Color MEDIUM = new Color(217, 119, 6);
  static final Color LOW = new Color(152, 162, 179);
  static final Color AMBER_BG = new Color(254, 243, 199);
  static final Color AMBER_TEXT = new Color(146, 64, 14);
  static final Color RED_BG = new Color(254, 226, 226);
  static final Color RED_TEXT = new Color(153, 27, 27);

  private ReportPdf() {}

  static Font font(float size, int style, Color color) {
    return new Font(Font.HELVETICA, size, style, color);
  }

  static Font body() {
    return font(9, Font.NORMAL, TEXT);
  }

  static Font small() {
    return font(8, Font.NORMAL, TEXT);
  }

  static Font muted() {
    return font(8, Font.NORMAL, MUTED);
  }

  static Font mono() {
    return new Font(Font.COURIER, 7.6f, Font.NORMAL, TEXT);
  }

  /** A section heading, with an optional grey note after it. */
  static void heading(Document doc, String title, String note) throws Exception {
    Paragraph p = new Paragraph();
    p.add(new Chunk(title, font(12, Font.BOLD, ACCENT)));
    if (note != null) p.add(new Chunk("   " + note, font(8, Font.NORMAL, FAINT)));
    p.setSpacingBefore(14);
    p.setSpacingAfter(6);
    doc.add(p);
  }

  static void subheading(Document doc, String title) throws Exception {
    Paragraph p = new Paragraph(title, font(9.5f, Font.BOLD, TEXT));
    p.setSpacingBefore(8);
    p.setSpacingAfter(4);
    doc.add(p);
  }

  static void para(Document doc, String text, Font f) throws Exception {
    Paragraph p = new Paragraph(text, f);
    p.setSpacingAfter(4);
    doc.add(p);
  }

  /** A full-width table with these relative column widths and a quiet header row. */
  static PdfPTable table(float[] widths, String... headers) {
    PdfPTable t = new PdfPTable(widths);
    t.setWidthPercentage(100);
    t.setSpacingBefore(2);
    t.setSpacingAfter(8);
    t.setHeaderRows(headers.length > 0 ? 1 : 0);
    for (String h : headers) {
      PdfPCell c = new PdfPCell(new Phrase(h, font(7.4f, Font.BOLD, FAINT)));
      c.setBorder(Rectangle.BOTTOM);
      c.setBorderColor(RULE);
      c.setPadding(3);
      c.setPaddingBottom(4);
      t.addCell(c);
    }
    return t;
  }

  static PdfPCell cell(String text, Font f) {
    return cell(new Phrase(text == null || text.isBlank() ? "—" : text, f));
  }

  static PdfPCell cell(Phrase phrase) {
    PdfPCell c = new PdfPCell(phrase);
    c.setBorder(Rectangle.TOP);
    c.setBorderColor(ROW_LINE);
    c.setPadding(3);
    c.setPaddingBottom(4);
    return c;
  }

  static PdfPCell right(String text, Font f) {
    PdfPCell c = cell(text, f);
    c.setHorizontalAlignment(Element.ALIGN_RIGHT);
    return c;
  }

  /** A shaded row across the table that names the group below it. */
  static void groupRow(PdfPTable t, String text) {
    PdfPCell c = new PdfPCell(new Phrase(text, font(8, Font.BOLD, ACCENT)));
    c.setColspan(t.getNumberOfColumns());
    c.setBackgroundColor(ACCENT_BG);
    c.setBorder(Rectangle.TOP);
    c.setBorderColor(ACCENT_LINE);
    c.setPadding(3);
    c.setPaddingBottom(4);
    t.addCell(c);
  }

  /** A small rounded-looking tag after a name, e.g. "moved" or "same address". */
  static Chunk tag(String text, boolean red) {
    Chunk c = new Chunk(" " + text + " ", font(6.6f, Font.BOLD, red ? RED_TEXT : AMBER_TEXT));
    c.setBackground(red ? RED_BG : AMBER_BG, 0, 1, 0, 1);
    return c;
  }

  /** A finding: a box with a coloured left edge, its title, and a sentence or two. */
  static PdfPTable finding(ReportFindings.Finding f) {
    PdfPTable t = new PdfPTable(1);
    t.setWidthPercentage(100);
    t.setSpacingAfter(5);
    Paragraph p = new Paragraph();
    p.add(new Chunk(f.title(), font(9.2f, Font.BOLD, TEXT)));
    p.add(Chunk.NEWLINE);
    p.add(new Chunk(f.body(), font(8.4f, Font.NORMAL, TEXT)));
    p.add(new Chunk("  " + f.source(), font(7.2f, Font.NORMAL, FAINT)));
    p.setLeading(11);
    PdfPCell c = new PdfPCell();
    c.addElement(p);
    c.setBorderColor(RULE);
    c.setBorderWidth(0.6f);
    c.setBorderColorLeft(switch (f.level()) {
      case HIGH -> HIGH;
      case MEDIUM -> MEDIUM;
      case LOW -> LOW;
    });
    c.setBorderWidthLeft(3f);
    c.setPadding(6);
    c.setPaddingTop(2);
    t.addCell(c);
    return t;
  }

  /** The figures under the title: big numbers with a word under each. */
  static PdfPTable figures(String[][] pairs) {
    PdfPTable t = new PdfPTable(pairs.length);
    t.setWidthPercentage(100);
    t.setSpacingBefore(8);
    t.setSpacingAfter(4);
    for (String[] p : pairs) {
      Paragraph para = new Paragraph();
      para.add(new Chunk(p[0], font(15, Font.BOLD, TEXT)));
      para.add(Chunk.NEWLINE);
      para.add(new Chunk(p[1], font(8, Font.NORMAL, MUTED)));
      PdfPCell c = new PdfPCell();
      c.addElement(para);
      c.setBorder(Rectangle.NO_BORDER);
      c.setPadding(0);
      t.addCell(c);
    }
    return t;
  }

  /** Each page's running header (what the report is) and footer (the capture, and "n of N"). */
  static final class Furniture extends PdfPageEventHelper {
    private final String header;
    private final String footer;
    private PdfTemplate total;
    private BaseFont base;

    Furniture(String header, String footer) {
      this.header = header;
      this.footer = footer;
    }

    @Override
    public void onOpenDocument(PdfWriter writer, Document document) {
      total = writer.getDirectContent().createTemplate(40, 12);
      try {
        base = BaseFont.createFont(BaseFont.HELVETICA, BaseFont.WINANSI, BaseFont.NOT_EMBEDDED);
      } catch (Exception e) {
        throw new IllegalStateException(e);
      }
    }

    @Override
    public void onEndPage(PdfWriter writer, Document document) {
      PdfContentByte cb = writer.getDirectContent();
      Rectangle page = document.getPageSize();
      float left = document.left();
      float right = document.right();
      Font f = font(7.4f, Font.NORMAL, FAINT);
      float top = page.getTop() - 28;
      ColumnText.showTextAligned(cb, Element.ALIGN_LEFT, new Phrase(header, f), left, top, 0);
      cb.setColorStroke(RULE);
      cb.setLineWidth(0.5f);
      cb.moveTo(left, top - 5);
      cb.lineTo(right, top - 5);
      cb.stroke();
      float bottom = page.getBottom() + 20;
      ColumnText.showTextAligned(cb, Element.ALIGN_LEFT, new Phrase(footer, f), left, bottom, 0);
      String n = writer.getPageNumber() + " of ";
      float w = base.getWidthPoint("000", 7.4f);
      ColumnText.showTextAligned(cb, Element.ALIGN_RIGHT, new Phrase(n, f), right - w, bottom, 0);
      cb.addTemplate(total, right - w + 2, bottom);
    }

    @Override
    public void onCloseDocument(PdfWriter writer, Document document) {
      total.beginText();
      total.setFontAndSize(base, 7.4f);
      total.setColorFill(FAINT);
      total.showText(String.valueOf(writer.getPageNumber() - 1));
      total.endText();
    }
  }
}
