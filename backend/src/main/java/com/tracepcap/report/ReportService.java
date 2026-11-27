package com.tracepcap.report;

import com.tracepcap.common.text.Humanize;
import static com.tracepcap.report.ReportPdf.cell;
import static com.tracepcap.report.ReportPdf.font;
import static com.tracepcap.report.ReportPdf.heading;
import static com.tracepcap.report.ReportPdf.para;
import static com.tracepcap.report.ReportPdf.right;
import static com.tracepcap.report.ReportPdf.table;

import com.lowagie.text.Chunk;
import com.lowagie.text.Document;
import com.lowagie.text.Font;
import com.lowagie.text.Image;
import com.lowagie.text.PageSize;
import com.lowagie.text.Paragraph;
import com.lowagie.text.Phrase;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfWriter;
import com.tracepcap.analysis.dto.occupancy.DeviceMoveDto;
import com.tracepcap.analysis.dto.occupancy.HostOccupancyResponse;
import com.tracepcap.analysis.dto.segments.NetworkSegmentsResponse;
import com.tracepcap.analysis.spi.AnalysisSummaryLookup;
import com.tracepcap.analysis.spi.AnalysisSummaryLookup.CaptureSummary;
import com.tracepcap.analysis.spi.CaptureNetworkLookup;
import com.tracepcap.analysis.spi.ConversationLookup;
import com.tracepcap.analysis.spi.ConversationLookup.Breakdown;
import com.tracepcap.analysis.spi.ConversationLookup.ConversationFacts;
import com.tracepcap.analysis.spi.ConversationLookup.NamedTotals;
import com.tracepcap.analysis.spi.HostClassificationLookup;
import com.tracepcap.analysis.spi.HostClassificationLookup.HostFacts;
import com.tracepcap.cluster.dto.ClusterEdgeDto;
import com.tracepcap.cluster.dto.ClusterGraphResponse;
import com.tracepcap.cluster.dto.ClusterNodeDto;
import com.tracepcap.cluster.service.NetworkClusterService;
import com.tracepcap.common.exception.ResourceNotFoundException;
import com.tracepcap.extraction.entity.ExtractedFileEntity;
import com.tracepcap.extraction.repository.ExtractedFileRepository;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.repository.FileRepository;
import com.tracepcap.report.ReportRequest.Section;
import com.tracepcap.story.dto.Finding;
import com.tracepcap.story.dto.StoryResponse;
import com.tracepcap.story.service.StoryService;
import java.io.OutputStream;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * A capture's PDF report (#1152): a briefing for someone who will never open TracePcap — what
 * needs a look, the hosts by network with their names, the network map — and, when asked for, the
 * evidence after it: traffic, conversations, extracted files and an appendix of every flagged
 * conversation.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ReportService {

  /** Findings shown on the summary page; the rest are counted. */
  private static final int FINDINGS_SHOWN = 8;
  /** Rows per flag in the appendix. */
  private static final int APPENDIX_ROWS_PER_FLAG = 300;
  private static final int BUSIEST = 25;
  private static final int TOP_ORGS_ON_SUMMARY = 6;
  /** Internet addresses listed per organisation in the hosts table. */
  private static final int INTERNET_ADDRESSES_SHOWN = 6;

  private static final DateTimeFormatter DAY = DateTimeFormatter.ofPattern("d MMM yyyy");
  private static final DateTimeFormatter HM = DateTimeFormatter.ofPattern("HH:mm");
  private static final DateTimeFormatter HMS = DateTimeFormatter.ofPattern("HH:mm:ss");
  private static final DateTimeFormatter STAMP = DateTimeFormatter.ofPattern("d MMM yyyy HH:mm");

  private final FileRepository fileRepository;
  private final AnalysisSummaryLookup analysisSummaryLookup;
  private final ConversationLookup conversationLookup;
  private final HostClassificationLookup hostClassificationLookup;
  private final ExtractedFileRepository extractedFileRepository;
  private final StoryService storyService;
  private final com.tracepcap.analysis.spi.NetworkRuleOverlay networkRuleOverlay;
  private final CaptureNetworkLookup captureNetworkLookup;
  private final NetworkClusterService clusterService;

  /** Everything one report is drawn from, gathered once. */
  private record Facts(
      FileEntity file,
      CaptureSummary summary,
      List<ConversationFacts> conversations,
      List<ConversationFacts> flagged,
      List<HostFacts> hosts,
      NetworkSegmentsResponse networks,
      List<HostOccupancyResponse.ReusedAddress> shared,
      List<DeviceMoveDto> moves,
      ClusterGraphResponse orgs,
      Set<String> internet,
      ReportNames names,
      StoryResponse story,
      List<ExtractedFileEntity> extracted) {}

  @Transactional(readOnly = true)
  public void generateReport(UUID fileId, ReportRequest request, OutputStream out) {
    ReportRequest req = request != null ? request : new ReportRequest();
    Facts facts = gather(fileId, req.getNetworkId());
    Set<Section> sections = req.effectiveSections();

    Document doc = new Document(PageSize.A4, 40, 40, 54, 44);
    try {
      PdfWriter writer = PdfWriter.getInstance(doc, out);
      FileEntity file = facts.file();
      String hash = file.getFileHash();
      String footer = file.getFileName()
          + (hash != null && hash.length() > 16 ? "  ·  SHA-256 " + hash.substring(0, 8) + "…" + hash.substring(hash.length() - 8) : "");
      writer.setPageEvent(new ReportPdf.Furniture(
          "TracePcap · capture report · " + LocalDateTime.now().format(STAMP), footer));
      doc.open();

      List<ReportFindings.Finding> findings = ReportFindings.build(
          facts.flagged(), facts.conversations().size(), facts.names(), facts.shared(), facts.networks(),
          sections.contains(Section.APPENDIX));

      summaryPage(doc, facts, findings, sections, req);
      if (sections.contains(Section.HOSTS)) {
        doc.newPage();
        hosts(doc, facts);
      }
      if (sections.contains(Section.MAP) && req.getMapImage() != null && !req.getMapImage().isBlank()) {
        // The map gets a landscape page, so its labels print as large as they can.
        doc.setPageSize(PageSize.A4.rotate());
        doc.newPage();
        map(doc, req);
      }
      restOfReport(doc, facts, sections, req);
      doc.setPageSize(PageSize.A4);
      if (sections.contains(Section.STORY) && hasStory(facts)) {
        doc.newPage();
        story(doc, facts.story());
      }
      if (sections.contains(Section.TRAFFIC)) {
        doc.newPage();
        traffic(doc, facts);
      }
      if (sections.contains(Section.CONVERSATIONS)) {
        doc.newPage();
        conversations(doc, facts);
      }
      if (sections.contains(Section.EXTRACTED_FILES) && !facts.extracted().isEmpty()) {
        doc.newPage();
        extractedFiles(doc, facts.extracted());
      }
      if (sections.contains(Section.APPENDIX)) {
        doc.newPage();
        appendix(doc, facts);
      }
    } catch (Exception e) {
      log.error("PDF generation failed for file {}", fileId, e);
      throw new RuntimeException("Report generation failed", e);
    } finally {
      doc.close();
    }
  }

  // ── Gathering ────────────────────────────────────────────────────────────────

  private Facts gather(UUID fileId, UUID networkId) {
    FileEntity file = fileRepository.findById(fileId)
        .orElseThrow(() -> new ResourceNotFoundException("File not found: " + fileId));
    CaptureSummary summary = analysisSummaryLookup.summaryFor(fileId).orElse(null);
    List<ConversationFacts> all = conversationLookup.conversationFacts(fileId);
    if (networkId != null) {
      // Viewed in a network (#925): its own rules' matches count, the global rules it suppresses don't.
      Set<String> suppressed = networkRuleOverlay.suppressedNames(networkId);
      Map<UUID, List<String>> labels = networkRuleOverlay.labels(networkId, fileId);
      all = all.stream().map(c -> inNetwork(c, suppressed, labels.get(c.id()))).toList();
    }
    List<ConversationFacts> flagged = all.stream().filter(c -> !ReportFindings.flagsOf(c).isEmpty()).toList();
    List<HostFacts> hosts = hostClassificationLookup.hostFacts(fileId);
    NetworkSegmentsResponse networks = safe(() -> captureNetworkLookup.networks(fileId), null);
    List<HostOccupancyResponse.ReusedAddress> shared = safe(() -> captureNetworkLookup.sharedAddresses(fileId), List.of());
    List<DeviceMoveDto> moves = safe(() -> captureNetworkLookup.moves(fileId), List.of());
    ClusterGraphResponse orgs = safe(() -> clusterService.computeClusters(fileId, "asn", null, List.of(), networkId), null);

    Map<String, String> orgByIp = new HashMap<>();
    Set<String> internet = new HashSet<>();
    if (orgs != null && orgs.getClusters() != null) {
      for (ClusterNodeDto n : orgs.getClusters()) {
        if ("cluster:internal".equals(n.getId()) || n.getIpBytes() == null) continue;
        for (String ip : realHosts(n).keySet()) {
          orgByIp.put(ip, n.getLabel());
          internet.add(ip);
        }
      }
    }
    ReportNames names = new ReportNames(hosts, shared, networks, orgByIp);
    StoryResponse story = safe(() -> storyService.getStoryByFileId(fileId).orElse(null), null);
    List<ExtractedFileEntity> extracted = extractedFileRepository.findByFileIdOrderByCreatedAtAsc(fileId);
    return new Facts(file, summary, all, flagged, hosts, networks, shared, moves, orgs, internet, names, story, extracted);
  }

  private static <T> T safe(java.util.function.Supplier<T> s, T fallback) {
    try {
      T v = s.get();
      return v != null ? v : fallback;
    } catch (RuntimeException e) {
      log.warn("Report: a part couldn't be read and is left out: {}", e.toString());
      return fallback;
    }
  }

  // ── Summary page ─────────────────────────────────────────────────────────────

  private void summaryPage(
      Document doc, Facts f, List<ReportFindings.Finding> findings, Set<Section> sections, ReportRequest req)
      throws Exception {
    FileEntity file = f.file();
    doc.add(new Paragraph(file.getFileName(), font(17, Font.BOLD, ReportPdf.TEXT)));
    doc.add(new Paragraph(whenLine(f, req), ReportPdf.muted()));

    long local = localDevices(f);
    int networks = f.networks() == null ? 0 : f.networks().segments().size();
    doc.add(ReportPdf.figures(new String[][] {
      {String.valueOf(local), "devices on your networks"},
      {String.valueOf(networks), networks == 1 ? "network" : "networks"},
      {String.format("%,d", f.conversations().size()), "conversations"},
      {String.valueOf(f.internet().size()), "internet hosts"},
    }));

    if (sections.contains(Section.NEEDS_A_LOOK)) {
      heading(doc, "Needs a look", findings.isEmpty() ? null
          : findings.size() + (findings.size() == 1 ? " thing" : " things") + ", most serious first");
      if (findings.isEmpty()) {
        para(doc, "Nothing was flagged: no nDPI risks, Suricata alerts or rule matches, no address"
            + " that changed hands, and every device that asked for an address got one."
            + (f.file().isEnableSuricata() ? "" : " Suricata didn't run on this capture."), ReportPdf.body());
      } else {
        for (int i = 0; i < Math.min(FINDINGS_SHOWN, findings.size()); i++) doc.add(ReportPdf.finding(findings.get(i)));
        if (findings.size() > FINDINGS_SHOWN) {
          para(doc, "And " + (findings.size() - FINDINGS_SHOWN) + " more of lower concern"
              + (sections.contains(Section.APPENDIX) ? "; the appendix lists every flagged conversation." : "."), ReportPdf.muted());
        }
      }
    }

    List<ClusterNodeDto> orgs = orgsBySize(f);
    if (!orgs.isEmpty()) {
      heading(doc, "Where the traffic goes", "by organisation, from GeoIP and your network labels");
      long total = orgs.stream().mapToLong(ReportService::realBytes).sum();
      PdfPTable t = table(new float[] {5, 1.4f, 1.6f, 1.2f}, "Organisation", "Hosts", "Bytes", "Share");
      for (ClusterNodeDto n : orgs.subList(0, Math.min(TOP_ORGS_ON_SUMMARY, orgs.size()))) orgRow(t, n, total);
      doc.add(t);
      if (orgs.size() > TOP_ORGS_ON_SUMMARY) {
        para(doc, "And " + (orgs.size() - TOP_ORGS_ON_SUMMARY) + " more"
            + (sections.contains(Section.TRAFFIC) ? ", in Traffic." : "."), ReportPdf.muted());
      }
    }
  }

  private String whenLine(Facts f, ReportRequest req) {
    CaptureSummary s = f.summary();
    List<String> parts = new ArrayList<>();
    if (s != null && s.startTime() != null) {
      String when = s.startTime().format(DAY) + ", " + s.startTime().format(HM);
      if (s.endTime() != null) {
        when += " to " + (s.endTime().toLocalDate().equals(s.startTime().toLocalDate())
            ? s.endTime().format(HM) : s.endTime().format(DAY) + ", " + s.endTime().format(HM));
      }
      if (s.durationMs() != null) when += " (" + Humanize.span(s.durationMs()) + ")";
      parts.add(when);
    }
    if (s != null) parts.add(String.format("%,d packets", s.packetCount()));
    if (s != null) parts.add(Humanize.bytes(s.totalBytes()));
    parts.add(req.getNetworkId() != null ? "with a monitored network's detection rules" : "with the shared detection rules");
    return String.join(" · ", parts);
  }

  private static long localDevices(Facts f) {
    Set<String> local = new java.util.LinkedHashSet<>();
    for (HostFacts h : f.hosts()) if (h.ip() != null && isHost(h.ip()) && !f.internet().contains(h.ip())) local.add(h.ip());
    List<String[]> same = new ArrayList<>();
    for (DeviceMoveDto m : f.moves()) same.add(new String[] {m.fromIp(), m.toIp()});
    if (f.networks() != null) {
      Map<String, List<String>> gateways = new HashMap<>();
      for (var s : f.networks().segments())
        if (s.serverMac() != null && s.routers() != null) gateways.computeIfAbsent(s.serverMac(), k -> new ArrayList<>()).addAll(s.routers());
      for (List<String> g : gateways.values()) for (String r : g) same.add(new String[] {g.get(0), r});
    }
    long count = deviceCount(local, same);
    for (var r : f.shared()) if (local.contains(r.ip())) count += Math.max(0, r.occupancies().size() - 1);
    if (f.networks() != null) {
      for (var s : f.networks().segments()) count += s.unanswered().size();
      count += f.networks().unanswered().size();
    }
    return count;
  }

  /**
   * Devices among these addresses, merging only addresses known to be one device (a device that
   * moved; one DHCP server's gateways). Not by MAC: a routed subnet's hosts all carry the router's
   * MAC, and a phone with private addresses changes MAC.
   */
  static long deviceCount(Set<String> addresses, List<String[]> sameDevice) {
    Map<String, String> parent = new HashMap<>();
    for (String a : addresses) parent.put(a, a);
    java.util.function.UnaryOperator<String> find = x -> {
      String r = x;
      while (!parent.get(r).equals(r)) r = parent.get(r);
      return r;
    };
    for (String[] p : sameDevice) {
      if (!parent.containsKey(p[0]) || !parent.containsKey(p[1])) continue;
      String a = find.apply(p[0]);
      String b = find.apply(p[1]);
      if (!a.equals(b)) parent.put(b, a);
    }
    return addresses.stream().map(find).distinct().count();
  }

  // ── Hosts by network ─────────────────────────────────────────────────────────

  private record HostRow(String name, String note, boolean redNote, String address, String mac, String device, String vendor) {}

  private void hosts(Document doc, Facts f) throws Exception {
    heading(doc, "Hosts, by network", "names from DHCP, NetBIOS and DNS");
    ReportNames names = f.names();

    // Devices that moved: their first address folds into the row of the one they moved to.
    Map<String, DeviceMoveDto> movedTo = new HashMap<>();
    Set<String> movedFrom = new HashSet<>();
    for (DeviceMoveDto m : f.moves()) {
      movedTo.put(m.toIp() + "|" + m.mac(), m);
      movedFrom.add(m.fromIp() + "|" + m.mac());
    }
    Map<String, List<HostOccupancyResponse.Occupancy>> shared = new HashMap<>();
    for (var r : f.shared()) shared.put(r.ip(), r.occupancies());

    Map<String, List<HostRow>> groups = new LinkedHashMap<>();
    Map<String, String> groupTitles = new LinkedHashMap<>();
    if (f.networks() != null) {
      for (var s : f.networks().segments()) {
        groups.put(s.label(), new ArrayList<>());
        groupTitles.put(s.label(), s.label() + (s.cidr() != null ? " · " + s.cidr() : ""));
      }
    }
    String other = "Other local addresses";

    List<HostFacts> local = f.hosts().stream()
        .filter(h -> h.ip() != null && !f.internet().contains(h.ip()))
        .sorted(Comparator.comparing(h -> ipSortKey(h.ip())))
        .toList();
    for (HostFacts h : local) {
      if (movedFrom.contains(h.ip() + "|" + h.mac())) continue;
      String group = names.networkOf(h.ip());
      if (group == null || !groups.containsKey(group)) {
        group = other;
        groups.computeIfAbsent(other, k -> new ArrayList<>());
        groupTitles.putIfAbsent(other, other);
      }
      List<HostRow> rows = groups.get(group);
      var holders = shared.get(h.ip());
      if (holders != null && holders.size() > 1) {
        for (int i = 0; i < holders.size(); i++) {
          var o = holders.get(i);
          String when = o.getNetwork() != null ? "on " + o.getNetwork()
              : i == 0 ? (o.getEndsAt() != null ? "until " + o.getEndsAt().format(HMS) : null)
              : (o.getStartsAt() != null ? "from " + o.getStartsAt().format(HMS) : null);
          var cls = o.getClassification();
          rows.add(new HostRow(o.getHostname() != null ? o.getHostname() : "—", i > 0 ? "same address" : null, false,
              h.ip() + (when != null ? "  " + when : ""), o.getMac(),
              device(cls != null ? cls.getDeviceType() : null, false),
              vendor(cls != null ? cls.getManufacturer() : h.manufacturer())));
        }
        continue;
      }
      DeviceMoveDto move = movedTo.get(h.ip() + "|" + h.mac());
      boolean gateway = names.isGateway(h.ip());
      String name = h.hostname() != null && !h.hostname().isBlank() ? h.hostname() : gateway ? "Gateway" : "—";
      String address = move != null ? lastOctets(move.fromIp(), move.toIp()) : h.ip();
      rows.add(new HostRow(name, move != null ? "moved" : null, false, address, h.mac(), device(h.deviceType(), gateway), vendor(h.manufacturer())));
    }
    if (f.networks() != null) {
      for (var s : f.networks().segments())
        for (var u : s.unanswered())
          groups.get(s.label()).add(new HostRow(u.hostname() != null ? u.hostname() : "—", "no address", false, "—", u.mac(), "—", "—"));
      for (var u : f.networks().unanswered()) {
        groups.computeIfAbsent(other, k -> new ArrayList<>());
        groupTitles.putIfAbsent(other, other);
        groups.get(other).add(new HostRow(u.hostname() != null ? u.hostname() : "—", "no address", false, "—", u.mac(), "—", "—"));
      }
    }
    // Flag the devices a high finding names.
    Set<String> flaggedTargets = new HashSet<>();
    for (ConversationFacts c : f.flagged()) {
      if (c.findings() != null && c.findings().flowRisks() != null && c.findings().flowRisks().contains("unsafe_protocol")) {
        String from = ReportFindings.initiator(c);
        flaggedTargets.add(from.equals(c.flow().srcIp()) ? c.flow().dstIp() : c.flow().srcIp());
      }
    }

    PdfPTable t = table(new float[] {3.1f, 2.1f, 2.4f, 1.6f, 1.6f}, "Name", "Address", "MAC", "Device", "Vendor");
    Font mono = ReportPdf.mono();
    Font small = ReportPdf.small();
    for (var e : groups.entrySet()) {
      if (e.getValue().isEmpty()) continue;
      ReportPdf.groupRow(t, groupTitles.get(e.getKey()) + " · " + e.getValue().size());
      for (HostRow r : e.getValue()) {
        Phrase name = new Phrase(r.name(), small);
        if (r.note() != null) name.add(ReportPdf.tag(r.note(), r.redNote()));
        String ip = r.address().split(" ")[0];
        if (flaggedTargets.contains(ip) && "—".equals(r.address()) == false && r.note() == null) name.add(ReportPdf.tag("flagged", true));
        t.addCell(cell(name));
        t.addCell(cell(r.address(), mono));
        t.addCell(cell(r.mac(), mono));
        t.addCell(cell(r.device(), small));
        t.addCell(cell(r.vendor(), small));
      }
    }
    // Internet: by organisation, its addresses after it.
    List<ClusterNodeDto> orgs = orgsBySize(f);
    if (!orgs.isEmpty()) {
      ReportPdf.groupRow(t, "Internet · " + f.internet().size() + " hosts, " + orgs.size() + " organisations");
      for (ClusterNodeDto n : orgs) {
        List<String> ips = new ArrayList<>(realHosts(n).keySet());
        ips.sort(Comparator.comparing(ReportService::ipSortKey));
        t.addCell(cell(n.getLabel(), small));
        // A big organisation's addresses would fill pages; the Conversations part lists them all.
        String shown = ips.size() <= INTERNET_ADDRESSES_SHOWN ? String.join(", ", ips)
            : String.join(", ", ips.subList(0, INTERNET_ADDRESSES_SHOWN)) + " and " + (ips.size() - INTERNET_ADDRESSES_SHOWN) + " more";
        var c = cell(shown, mono);
        c.setColspan(4);
        t.addCell(c);
      }
    }
    doc.add(t);
  }

  // ── Map ──────────────────────────────────────────────────────────────────────

  private void map(Document doc, ReportRequest req) throws Exception {
    heading(doc, "Network map", "grouped as on the Network tab");
    if (req.getMapCaption() != null && !req.getMapCaption().isBlank()) para(doc, req.getMapCaption(), ReportPdf.muted());
    byte[] bytes = Base64.getDecoder().decode(req.getMapImage());
    Image img = Image.getInstance(bytes);
    float w = doc.right() - doc.left();
    float h = doc.top() - doc.bottom() - 120;
    img.scaleToFit(w, h);
    img.setSpacingBefore(4);
    doc.add(img);
  }

  /** After the briefing: what the rest of the report holds, and what it leaves out and why. */
  private void restOfReport(Document doc, Facts f, Set<Section> sections, ReportRequest req) throws Exception {
    List<String> inside = new ArrayList<>();
    if (sections.contains(Section.STORY) && hasStory(f)) inside.add("Story: the narrative and findings from the Story tab");
    if (sections.contains(Section.TRAFFIC)) inside.add("Traffic: where it goes, flows between organisations, protocols and apps");
    if (sections.contains(Section.CONVERSATIONS)) inside.add("Conversations: the busiest " + BUSIEST + ", and the internet hosts");
    if (sections.contains(Section.EXTRACTED_FILES) && !f.extracted().isEmpty()) inside.add("Extracted files: " + f.extracted().size());
    if (sections.contains(Section.APPENDIX)) inside.add("Appendix: every flagged conversation, by flag; how each device was classified");

    List<String> out = new ArrayList<>();
    if (!hasStory(f)) out.add("Story: not written for this capture yet");
    else if (!sections.contains(Section.STORY)) out.add("Story: left out");
    if (!f.file().isEnableFileExtraction()) out.add("Extracted files: extraction was off");
    else if (f.extracted().isEmpty()) out.add("Extracted files: none were found");
    if (sections.contains(Section.MAP) && (req.getMapImage() == null || req.getMapImage().isBlank())) out.add("Network map: it couldn't be drawn");
    for (Section s : List.of(Section.TRAFFIC, Section.CONVERSATIONS, Section.APPENDIX)) {
      if (!sections.contains(s)) out.add(sectionName(s) + ": left out");
    }
    if (inside.isEmpty() && out.isEmpty()) return;
    if (!inside.isEmpty()) {
      heading(doc, "The rest of this report", null);
      for (String s : inside) para(doc, "•  " + s, ReportPdf.body());
    }
    if (!out.isEmpty()) {
      Paragraph p = new Paragraph();
      p.add(new Chunk("Not in this report.  ", font(8, Font.BOLD, ReportPdf.MUTED)));
      p.add(new Chunk(String.join(" · ", out), ReportPdf.muted()));
      p.setSpacingBefore(8);
      doc.add(p);
    }
  }

  private static String sectionName(Section s) {
    return switch (s) {
      case NEEDS_A_LOOK -> "Needs a look";
      case HOSTS -> "Hosts";
      case MAP -> "Network map";
      case STORY -> "Story";
      case TRAFFIC -> "Traffic";
      case CONVERSATIONS -> "Conversations";
      case EXTRACTED_FILES -> "Extracted files";
      case APPENDIX -> "Appendix";
    };
  }

  // ── Story ────────────────────────────────────────────────────────────────────

  private static boolean hasStory(Facts f) {
    return f.story() != null && f.story().getNarrative() != null && !f.story().getNarrative().isEmpty();
  }

  private void story(Document doc, StoryResponse story) throws Exception {
    heading(doc, "Story", "written by the LLM from this capture's analysis; check it against the evidence");
    for (var section : story.getNarrative()) {
      if (section.getTitle() != null) ReportPdf.subheading(doc, section.getTitle());
      if (section.getContent() != null) para(doc, section.getContent(), ReportPdf.body());
    }
    if (story.getFindings() != null && !story.getFindings().isEmpty()) {
      ReportPdf.subheading(doc, "Its findings");
      PdfPTable t = table(new float[] {1.2f, 3, 6}, "Severity", "Finding", "Summary");
      for (Finding fi : story.getFindings()) {
        t.addCell(cell(fi.getSeverity() != null ? cap(fi.getSeverity().name()) : "—", ReportPdf.small()));
        t.addCell(cell(fi.getTitle(), font(8, Font.BOLD, ReportPdf.TEXT)));
        t.addCell(cell(fi.getSummary(), ReportPdf.small()));
      }
      doc.add(t);
    }
  }

  // ── Traffic ──────────────────────────────────────────────────────────────────

  private void traffic(Document doc, Facts f) throws Exception {
    List<ClusterNodeDto> orgs = orgsBySize(f);
    if (!orgs.isEmpty()) {
      heading(doc, "Where the traffic goes", "by organisation");
      long total = orgs.stream().mapToLong(ReportService::realBytes).sum();
      PdfPTable t = table(new float[] {5, 1.4f, 1.6f, 1.2f}, "Organisation", "Hosts", "Bytes", "Share");
      for (ClusterNodeDto n : orgs) orgRow(t, n, total);
      doc.add(t);
    }
    if (f.orgs() != null && f.orgs().getEdges() != null && !f.orgs().getEdges().isEmpty()) {
      Map<String, String> label = new HashMap<>();
      for (ClusterNodeDto n : f.orgs().getClusters()) label.put(n.getId(), n.getLabel());
      heading(doc, "Flows between organisations", null);
      PdfPTable t = table(new float[] {3.5f, 3.5f, 1.4f, 1.4f, 1.6f}, "From", "To", "Mostly", "Conversations", "Bytes");
      f.orgs().getEdges().stream().sorted(Comparator.comparingLong(ClusterEdgeDto::getTotalBytes).reversed()).limit(15)
          .forEach(e -> {
            t.addCell(cell(label.getOrDefault(e.getSourceId(), e.getSourceId()), ReportPdf.small()));
            t.addCell(cell(label.getOrDefault(e.getTargetId(), e.getTargetId()), ReportPdf.small()));
            t.addCell(cell(e.getDominantProtocol(), ReportPdf.small()));
            t.addCell(right(String.format("%,d", e.getConversationCount()), ReportPdf.small()));
            t.addCell(right(Humanize.bytes(e.getTotalBytes()), ReportPdf.small()));
          });
      doc.add(t);
    }
    if (f.summary() != null && f.summary().protocolStats() != null && !f.summary().protocolStats().isEmpty()) {
      heading(doc, "Protocols", "from tshark");
      PdfPTable t = table(new float[] {4, 2, 2, 1.5f}, "Protocol", "Packets", "Bytes", "Share");
      f.summary().protocolStats().entrySet().stream()
          .sorted((a, b) -> Long.compare(stat(b.getValue(), "bytes"), stat(a.getValue(), "bytes")))
          .forEach(e -> {
            t.addCell(cell(e.getKey(), ReportPdf.small()));
            t.addCell(right(String.format("%,d", stat(e.getValue(), "packetCount")), ReportPdf.small()));
            t.addCell(right(Humanize.bytes(stat(e.getValue(), "bytes")), ReportPdf.small()));
            t.addCell(right(String.format("%.1f%%", statD(e.getValue(), "percentage")), ReportPdf.small()));
          });
      doc.add(t);
    }
    named(doc, "Applications", "from nDPI", conversationLookup.breakdown(f.file().getId(), Breakdown.APPLICATION));
    named(doc, "Categories", "from nDPI", conversationLookup.breakdown(f.file().getId(), Breakdown.CATEGORY));
  }

  private void named(Document doc, String title, String note, List<NamedTotals> rows) throws Exception {
    if (rows == null || rows.isEmpty()) return;
    heading(doc, title, note);
    // Some breakdowns count packets only; a column of "0 B" would read as no traffic.
    boolean withBytes = rows.stream().anyMatch(n -> n.totalBytes() > 0);
    PdfPTable t = withBytes
        ? table(new float[] {4, 2, 2}, "Name", "Packets", "Bytes")
        : table(new float[] {6, 2}, "Name", "Packets");
    for (NamedTotals n : rows) {
      t.addCell(cell(n.name(), ReportPdf.small()));
      t.addCell(right(String.format("%,d", n.packetCount()), ReportPdf.small()));
      if (withBytes) t.addCell(right(Humanize.bytes(n.totalBytes()), ReportPdf.small()));
    }
    doc.add(t);
  }

  // ── Conversations ────────────────────────────────────────────────────────────

  private void conversations(Document doc, Facts f) throws Exception {
    heading(doc, "Busiest conversations", "the " + BUSIEST + " that moved the most bytes");
    List<ConversationFacts> busiest = f.conversations().stream()
        .sorted(Comparator.comparingLong((ConversationFacts c) -> c.flow().totalBytes()).reversed())
        .limit(BUSIEST).toList();
    doc.add(conversationTable(busiest, f.names(), false));

    List<ClusterNodeDto> orgs = orgsBySize(f);
    if (!orgs.isEmpty()) {
      heading(doc, "Internet hosts", null);
      PdfPTable t = table(new float[] {2.4f, 4, 1.6f, 1.6f}, "Address", "Organisation", "Conversations", "Bytes");
      List<String[]> rows = new ArrayList<>();
      for (ClusterNodeDto n : orgs) {
        for (var e : realHosts(n).entrySet()) {
          long convs = n.getIpConversations() != null ? n.getIpConversations().getOrDefault(e.getKey(), 0L) : 0;
          rows.add(new String[] {e.getKey(), n.getLabel(), String.valueOf(convs), String.valueOf(e.getValue())});
        }
      }
      rows.sort(Comparator.comparingLong((String[] r) -> Long.parseLong(r[3])).reversed());
      for (String[] r : rows) {
        t.addCell(cell(r[0], ReportPdf.mono()));
        t.addCell(cell(r[1], ReportPdf.small()));
        t.addCell(right(String.format("%,d", Long.parseLong(r[2])), ReportPdf.small()));
        t.addCell(right(Humanize.bytes(Long.parseLong(r[3])), ReportPdf.small()));
      }
      doc.add(t);
    }
  }

  private PdfPTable conversationTable(List<ConversationFacts> rows, ReportNames names, boolean withFlags) {
    PdfPTable t = withFlags
        ? table(new float[] {1.3f, 3, 3.4f, 1.4f, 1.3f, 3}, "When", "From", "To", "App", "Bytes", "Flags")
        : table(new float[] {1.3f, 3.2f, 3.6f, 1.6f, 1.2f, 1.4f}, "When", "From", "To", "App", "Packets", "Bytes");
    for (ConversationFacts c : rows) {
      var fl = c.flow();
      String from = ReportFindings.initiator(c);
      boolean fwd = from.equals(fl.srcIp());
      String to = fwd ? fl.dstIp() : fl.srcIp();
      Integer port = fwd ? fl.dstPort() : fl.srcPort();
      t.addCell(cell(fl.startTime() != null ? fl.startTime().format(HMS) : "—", ReportPdf.mono()));
      t.addCell(cell(names.label(from, fl.startTime()), ReportPdf.small()));
      t.addCell(cell(names.label(to, fl.startTime()) + (port != null ? " :" + port : ""), ReportPdf.small()));
      t.addCell(cell(ReportFindings.app(c), ReportPdf.small()));
      if (withFlags) {
        t.addCell(right(Humanize.bytes(fl.totalBytes()), ReportPdf.small()));
        t.addCell(cell(ReportFindings.flagText(c), font(7.2f, Font.NORMAL, ReportPdf.MUTED)));
      } else {
        t.addCell(right(String.format("%,d", fl.packetCount()), ReportPdf.small()));
        t.addCell(right(Humanize.bytes(fl.totalBytes()), ReportPdf.small()));
      }
    }
    return t;
  }

  // ── Extracted files ──────────────────────────────────────────────────────────

  private void extractedFiles(Document doc, List<ExtractedFileEntity> files) throws Exception {
    heading(doc, "Extracted files", files.size() + " carved from the capture");
    PdfPTable t = table(new float[] {4, 2.6f, 1.4f, 1.6f, 5}, "File", "Type", "Size", "From", "SHA-256");
    for (ExtractedFileEntity ef : files) {
      t.addCell(cell(ef.getFilename(), ReportPdf.small()));
      t.addCell(cell(ef.getMimeType(), ReportPdf.small()));
      t.addCell(right(ef.getFileSize() != null ? Humanize.bytes(ef.getFileSize()) : "—", ReportPdf.small()));
      t.addCell(cell(ef.getExtractionMethod(), ReportPdf.small()));
      t.addCell(cell(ef.getSha256(), font(6.4f, Font.NORMAL, ReportPdf.TEXT)));
    }
    doc.add(t);
  }

  // ── Appendix ─────────────────────────────────────────────────────────────────

  private void appendix(Document doc, Facts f) throws Exception {
    heading(doc, "Appendix: every flagged conversation", f.flagged().size() + " of "
        + String.format("%,d", f.conversations().size()) + ", by flag");
    if (f.flagged().isEmpty()) para(doc, "None.", ReportPdf.body());
    Map<String, List<ConversationFacts>> byFlag = new LinkedHashMap<>();
    for (ConversationFacts c : f.flagged())
      for (String k : ReportFindings.flagKeys(c)) byFlag.computeIfAbsent(k, x -> new ArrayList<>()).add(c);
    List<Map.Entry<String, List<ConversationFacts>>> groups = new ArrayList<>(byFlag.entrySet());
    groups.sort(Comparator.comparingInt(e -> e.getValue().size()));
    for (var e : groups) {
      List<ConversationFacts> rows = e.getValue().stream()
          .sorted(Comparator.comparing((ConversationFacts c) -> c.flow().startTime(), Comparator.nullsLast(Comparator.naturalOrder())))
          .toList();
      ReportPdf.subheading(doc, e.getKey() + " · " + rows.size());
      doc.add(conversationTable(rows.subList(0, Math.min(APPENDIX_ROWS_PER_FLAG, rows.size())), f.names(), true));
      if (rows.size() > APPENDIX_ROWS_PER_FLAG) {
        para(doc, "And " + (rows.size() - APPENDIX_ROWS_PER_FLAG) + " more; filter the Conversations tab by this flag to see them.", ReportPdf.muted());
      }
    }

    doc.newPage();
    heading(doc, "How each device was classified", "from its MAC vendor, TTL and traffic");
    PdfPTable t = table(new float[] {2.6f, 2.4f, 1.6f, 1, 5}, "Device", "Address", "Type", "Conf.", "Evidence");
    for (HostFacts h : f.hosts().stream().sorted(Comparator.comparing(h -> ipSortKey(h.ip()))).toList()) {
      t.addCell(cell(h.hostname() != null ? h.hostname() : f.names().isGateway(h.ip()) ? "Gateway" : "—", ReportPdf.small()));
      t.addCell(cell(h.ip(), ReportPdf.mono()));
      t.addCell(cell(device(h.deviceType(), false), ReportPdf.small()));
      t.addCell(right(h.confidence() + "%", ReportPdf.small()));
      t.addCell(cell(buildHostEvidence(h), font(7.2f, Font.NORMAL, ReportPdf.MUTED)));
    }
    doc.add(t);
    para(doc, "A gateway can read as a laptop or server here: classification goes by its MAC vendor"
        + " and traffic, while the hosts table names it from the DHCP leases it handed out.", ReportPdf.muted());
  }

  // ── Small helpers ────────────────────────────────────────────────────────────

  private static List<ClusterNodeDto> orgsBySize(Facts f) {
    if (f.orgs() == null || f.orgs().getClusters() == null) return List.of();
    return f.orgs().getClusters().stream()
        .filter(n -> !"cluster:internal".equals(n.getId()) && !realHosts(n).isEmpty())
        .sorted(Comparator.comparingLong(ReportService::realBytes).reversed())
        .toList();
  }

  private static void orgRow(PdfPTable t, ClusterNodeDto n, long total) {
    long b = realBytes(n);
    t.addCell(cell(n.getLabel(), ReportPdf.small()));
    t.addCell(right(String.valueOf(realHosts(n).size()), ReportPdf.small()));
    t.addCell(right(Humanize.bytes(b), ReportPdf.small()));
    t.addCell(right(total > 0 ? String.format("%.1f%%", 100.0 * b / total) : "—", ReportPdf.small()));
  }

  /** An organisation's hosts, less the addresses that aren't one (0.0.0.0, broadcast, multicast). */
  static Map<String, Long> realHosts(ClusterNodeDto n) {
    if (n.getIpBytes() == null) return Map.of();
    Map<String, Long> out = new LinkedHashMap<>();
    n.getIpBytes().forEach((ip, b) -> { if (isHost(ip)) out.put(ip, b); });
    return out;
  }

  private static long realBytes(ClusterNodeDto n) {
    return realHosts(n).values().stream().mapToLong(Long::longValue).sum();
  }

  /** False for the unspecified, broadcast and multicast addresses, which no device holds. */
  static boolean isHost(String ip) {
    if (ip == null || ip.equals("0.0.0.0") || ip.equals("::") || ip.equals("255.255.255.255")) return false;
    if (ip.toLowerCase().startsWith("ff")) return false;
    int dot = ip.indexOf('.');
    if (dot > 0) {
      int first = parseOr(ip.substring(0, dot));
      if (first >= 224 && first <= 239) return false;
    }
    return true;
  }

  /** "LAPTOP_DESKTOP" → "Laptop/desktop"; a DHCP gateway is a gateway whatever its traffic says. */
  static String device(String type, boolean gateway) {
    if (gateway) return "Gateway";
    if (type == null || type.isBlank() || type.equals("UNKNOWN")) return "—";
    return switch (type) {
      case "LAPTOP_DESKTOP" -> "Laptop/desktop";
      case "DNS_SERVER" -> "DNS server";
      case "IOT" -> "IoT";
      default -> cap(type.replace('_', ' '));
    };
  }

  /** A vendor without its legal suffix: "Dell Inc." → "Dell", "Hangzhou Hikvision … Co.,Ltd." → "Hangzhou Hikvision". */
  static String vendor(String manufacturer) {
    if (manufacturer == null || manufacturer.isBlank()) return "—";
    String v = manufacturer.replaceAll("(?i)[,.]?\\s*(inc\\.?|incorporated|corporation|corporate|corp\\.?|co\\.?,?\\s*ltd\\.?|ltd\\.?|llc|gmbh|limited|electronics|digital technology|technology|technologies)\\b\\.?", "").trim();
    v = v.replaceAll("[,.]+$", "").trim();
    String[] words = v.split("\\s+");
    if (words.length > 2) v = words[0] + " " + words[1];
    return v.isBlank() ? manufacturer : v;
  }

  private static String lastOctets(String from, String to) {
    int dot = from.lastIndexOf('.');
    if (dot > 0 && to.startsWith(from.substring(0, dot + 1))) return from + " → ." + to.substring(dot + 1);
    return from + " → " + to;
  }

  private static String ipSortKey(String ip) {
    if (ip == null) return "";
    String[] o = ip.split("\\.");
    if (o.length != 4) return "~" + ip;
    StringBuilder sb = new StringBuilder();
    for (String s : o) sb.append(String.format("%03d", parseOr(s)));
    return sb.toString();
  }

  private static int parseOr(String s) {
    try {
      return Integer.parseInt(s);
    } catch (NumberFormatException e) {
      return 0;
    }
  }

  private static String cap(String s) {
    String l = s.toLowerCase();
    return Character.toUpperCase(l.charAt(0)) + l.substring(1);
  }

  private static long stat(Object stat, String key) {
    if (stat instanceof Map<?, ?> m && m.get(key) instanceof Number n) return n.longValue();
    return 0L;
  }

  private static double statD(Object stat, String key) {
    if (stat instanceof Map<?, ?> m && m.get(key) instanceof Number n) return n.doubleValue();
    return 0.0;
  }

  // ── Classification evidence (characterised in ReportHeuristicsCharacterisationTest) ──

  private String ttlFingerprint(Integer ttl) {
    if (ttl == null) return "—";
    if (ttl > 128) return "TTL " + ttl + " → Network device";
    if (ttl > 64) return "TTL " + ttl + " → Windows";
    return "TTL " + ttl + " → Linux/Unix/iOS";
  }

  private String buildHostEvidence(HostFacts h) {
    StringBuilder sb = new StringBuilder();
    if (h.manufacturer() != null) {
      sb.append("MAC vendor: ").append(h.manufacturer());
      String hint = vendorDeviceHint(h.manufacturer());
      if (hint != null) sb.append(" (→ ").append(device(hint, false)).append(")");
    } else if (h.mac() != null) {
      sb.append("MAC present, vendor unknown");
    } else {
      sb.append("No MAC data");
    }
    if (h.ttl() != null) sb.append("; TTL ").append(h.ttl()).append(" → ").append(ttlOs(h.ttl()));
    if (h.confidence() == 100) sb.append("; YAML rule override (confidence 100%)");
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

  static ConversationFacts inNetwork(ConversationFacts c, Set<String> suppressed, List<String> networkNames) {
    var f = c.findings();
    java.util.LinkedHashSet<String> sigs = new java.util.LinkedHashSet<>();
    if (f.customSignatures() != null) {
      for (String n : f.customSignatures()) if (!suppressed.contains(n)) sigs.add(n);
    }
    if (networkNames != null) sigs.addAll(networkNames);
    var findings =
        new ConversationLookup.Findings(
            f.appName(), f.tsharkProtocol(), f.category(), f.flowRisks(), f.suricataAlerts(),
            List.copyOf(sigs), f.httpUserAgents());
    return new ConversationFacts(c.id(), c.fileId(), c.flow(), c.tls(), findings);
  }
}
