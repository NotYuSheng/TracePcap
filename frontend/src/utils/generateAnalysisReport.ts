import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';
import { conversationService } from '@/features/conversation/services/conversationService';
import { storyService } from '@/features/story/services/storyService';
import { networkService } from '@/features/network/services/networkService';
import type { AnalysisSummary, Conversation, Story } from '@/types';
import type { GraphNode, NetworkStats } from '@/features/network/types';

// ─── Helpers ────────────────────────────────────────────────────────────────

function fmtBytes(bytes: number): string {
  if (bytes >= 1_048_576) return `${(bytes / 1_048_576).toFixed(2)} MB`;
  if (bytes >= 1_024) return `${(bytes / 1_024).toFixed(2)} KB`;
  return `${bytes} B`;
}

function fmtTs(ts: number): string {
  if (!ts) return '—';
  // Handle both millisecond and second timestamps
  const ms = ts > 1e10 ? ts : ts * 1000;
  return new Date(ms).toLocaleString();
}

function fmtDuration(ms: number): string {
  if (ms < 1000) return `${ms} ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(2)} s`;
  return `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`;
}

// ─── PDF builder helpers ─────────────────────────────────────────────────────

const MARGIN = 14;
const LINE = 7;
const SECTION_GAP = 10;

type DocState = { y: number };

function pageHeight(doc: jsPDF) {
  return doc.internal.pageSize.getHeight();
}
function pageWidth(doc: jsPDF) {
  return doc.internal.pageSize.getWidth();
}
function contentWidth(doc: jsPDF) {
  return pageWidth(doc) - MARGIN * 2;
}

function checkBreak(doc: jsPDF, state: DocState, needed = LINE) {
  if (state.y + needed > pageHeight(doc) - 20) {
    doc.addPage();
    state.y = 20;
  }
}

function sectionTitle(doc: jsPDF, state: DocState, title: string) {
  checkBreak(doc, state, 14);
  doc.setFontSize(13);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(30, 80, 160);
  doc.text(title, MARGIN, state.y);
  state.y += 2;
  doc.setDrawColor(30, 80, 160);
  doc.setLineWidth(0.4);
  doc.line(MARGIN, state.y, MARGIN + contentWidth(doc), state.y);
  state.y += LINE;
  doc.setTextColor(0, 0, 0);
}

function kv(doc: jsPDF, state: DocState, label: string, value: string, labelWidth = 55) {
  checkBreak(doc, state);
  doc.setFontSize(10);
  doc.setFont('helvetica', 'bold');
  doc.text(label, MARGIN, state.y);
  doc.setFont('helvetica', 'normal');
  doc.text(value, MARGIN + labelWidth, state.y);
  state.y += LINE;
}

function bodyText(doc: jsPDF, state: DocState, text: string) {
  const lines = doc.splitTextToSize(text, contentWidth(doc));
  lines.forEach((line: string) => {
    checkBreak(doc, state);
    doc.setFontSize(10);
    doc.setFont('helvetica', 'normal');
    doc.text(line, MARGIN, state.y);
    state.y += LINE;
  });
}

function addFooters(doc: jsPDF) {
  const total = (doc.internal as any).getNumberOfPages();
  for (let i = 1; i <= total; i++) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(150, 150, 150);
    doc.text(
      `Page ${i} of ${total}`,
      pageWidth(doc) / 2,
      pageHeight(doc) - 8,
      { align: 'center' }
    );
    doc.setTextColor(0, 0, 0);
  }
}

// ─── Section renderers ───────────────────────────────────────────────────────

function renderOverview(doc: jsPDF, state: DocState, data: AnalysisSummary, fileId: string) {
  sectionTitle(doc, state, '1. Overview');
  kv(doc, state, 'File Name:', data.fileName ?? fileId ?? '—');
  kv(doc, state, 'File ID:', data.fileId ?? fileId ?? '—');
  kv(doc, state, 'File Size:', data.fileSize ? fmtBytes(data.fileSize) : '—');
  kv(doc, state, 'Upload Time:', fmtTs(data.uploadTime));
  kv(doc, state, 'Total Packets:', data.totalPackets?.toLocaleString() ?? '—');
  kv(doc, state, 'Unique Hosts:', data.uniqueHosts?.length?.toString() ?? '—');
  kv(doc, state, 'Conversations:', data.topConversations?.length?.toString() ?? '—');

  if (data.timeRange?.length === 2) {
    kv(doc, state, 'Capture Start:', fmtTs(data.timeRange[0]));
    kv(doc, state, 'Capture End:', fmtTs(data.timeRange[1]));
    const dur = data.timeRange[1] - data.timeRange[0];
    kv(doc, state, 'Duration:', `${dur.toFixed(2)} s`);
  }
  state.y += SECTION_GAP;

  // Protocol distribution table
  if (data.protocolDistribution?.length) {
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.text('Protocol Distribution', MARGIN, state.y);
    state.y += LINE;

    autoTable(doc, {
      startY: state.y,
      head: [['Protocol', 'Packets', 'Bytes', '%']],
      body: data.protocolDistribution.map(p => [
        p.protocol,
        p.count.toLocaleString(),
        fmtBytes(p.bytes),
        `${p.percentage.toFixed(1)}%`,
      ]),
      styles: { fontSize: 9 },
      headStyles: { fillColor: [30, 80, 160] },
      margin: { left: MARGIN, right: MARGIN },
    });
    state.y = (doc as any).lastAutoTable.finalY + SECTION_GAP;
  }

  // Five W's
  if (data.fiveWs) {
    const { who, what, when, where, why } = data.fiveWs;

    if (who?.hosts?.length) {
      doc.setFontSize(11);
      doc.setFont('helvetica', 'bold');
      checkBreak(doc, state, 14);
      doc.text('Who — Hosts & Roles', MARGIN, state.y);
      state.y += LINE;
      autoTable(doc, {
        startY: state.y,
        head: [['IP Address', 'Role', 'Bytes Sent', 'Bytes Received']],
        body: who.hosts.slice(0, 20).map(h => [
          h.endpoint?.ip ?? '?',
          h.role ?? '?',
          fmtBytes(h.bytesSent ?? 0),
          fmtBytes(h.bytesReceived ?? 0),
        ]),
        styles: { fontSize: 9 },
        headStyles: { fillColor: [30, 80, 160] },
        margin: { left: MARGIN, right: MARGIN },
      });
      state.y = (doc as any).lastAutoTable.finalY + SECTION_GAP;
    }

    if (what) {
      checkBreak(doc, state, 14);
      doc.setFontSize(11);
      doc.setFont('helvetica', 'bold');
      doc.text('What — Services & Data', MARGIN, state.y);
      state.y += LINE;
      if (what.dataTransferred) kv(doc, state, 'Total Transferred:', fmtBytes(what.dataTransferred));
      if (what.services?.length) {
        autoTable(doc, {
          startY: state.y,
          head: [['Service', 'Port', 'Protocol', 'Packets', 'Bytes']],
          body: what.services.slice(0, 15).map(s => [
            s.name,
            s.port.toString(),
            s.protocol,
            s.packetCount.toLocaleString(),
            fmtBytes(s.bytes),
          ]),
          styles: { fontSize: 9 },
          headStyles: { fillColor: [30, 80, 160] },
          margin: { left: MARGIN, right: MARGIN },
        });
        state.y = (doc as any).lastAutoTable.finalY + SECTION_GAP;
      }
    }

    if (when) {
      checkBreak(doc, state, 14);
      doc.setFontSize(11);
      doc.setFont('helvetica', 'bold');
      doc.text('When — Timeline', MARGIN, state.y);
      state.y += LINE;
      doc.setFont('helvetica', 'normal');
      kv(doc, state, 'Start:', fmtTs(when.startTime));
      kv(doc, state, 'End:', fmtTs(when.endTime));
      if (when.duration) kv(doc, state, 'Duration:', `${when.duration.toFixed(2)} s`);
      state.y += SECTION_GAP;
    }

    if (where) {
      checkBreak(doc, state, 14);
      doc.setFontSize(11);
      doc.setFont('helvetica', 'bold');
      doc.text('Where — Networks', MARGIN, state.y);
      state.y += LINE;
      doc.setFont('helvetica', 'normal');
      if (where.internalNetworks?.length) kv(doc, state, 'Internal:', where.internalNetworks.join(', '));
      if (where.externalNetworks?.length) kv(doc, state, 'External:', where.externalNetworks.join(', '));
      state.y += SECTION_GAP;
    }

    if (why) {
      checkBreak(doc, state, 14);
      doc.setFontSize(11);
      doc.setFont('helvetica', 'bold');
      doc.text('Why — Purposes & Anomalies', MARGIN, state.y);
      state.y += LINE;
      doc.setFont('helvetica', 'normal');
      why.purposes?.forEach(p => bodyText(doc, state, `• ${p}`));
      if (why.anomalies?.length) {
        autoTable(doc, {
          startY: state.y,
          head: [['Severity', 'Type', 'Description']],
          body: why.anomalies.map(a => [
            a.severity.toUpperCase(),
            a.type,
            a.description,
          ]),
          styles: { fontSize: 9 },
          headStyles: { fillColor: [160, 40, 40] },
          margin: { left: MARGIN, right: MARGIN },
        });
        state.y = (doc as any).lastAutoTable.finalY + SECTION_GAP;
      }
    }
  }
}

function renderConversations(doc: jsPDF, state: DocState, conversations: Conversation[]) {
  doc.addPage();
  state.y = 20;
  sectionTitle(doc, state, '2. Conversations');

  if (!conversations.length) {
    bodyText(doc, state, 'No conversation data available.');
    return;
  }

  autoTable(doc, {
    startY: state.y,
    head: [['Source', 'Destination', 'Protocol', 'Packets', 'Bytes', 'Duration']],
    body: conversations.map(c => {
      const src = c.endpoints[0];
      const dst = c.endpoints[1];
      const dur = c.endTime && c.startTime ? c.endTime - c.startTime : 0;
      return [
        `${src.ip}${src.port ? `:${src.port}` : ''}`,
        `${dst.ip}${dst.port ? `:${dst.port}` : ''}`,
        c.protocol.name,
        c.packetCount.toLocaleString(),
        fmtBytes(c.totalBytes),
        fmtDuration(dur),
      ];
    }),
    styles: { fontSize: 8, overflow: 'linebreak' },
    headStyles: { fillColor: [30, 80, 160] },
    columnStyles: { 2: { cellWidth: 22 }, 3: { cellWidth: 20 }, 4: { cellWidth: 22 }, 5: { cellWidth: 24 } },
    margin: { left: MARGIN, right: MARGIN },
  });
  state.y = (doc as any).lastAutoTable.finalY + SECTION_GAP;
}

function renderStory(doc: jsPDF, state: DocState, story: Story) {
  doc.addPage();
  state.y = 20;
  sectionTitle(doc, state, '3. Story — AI Narrative Analysis');

  // Highlights
  if (story.highlights?.length) {
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.text('Key Highlights', MARGIN, state.y);
    state.y += LINE;
    autoTable(doc, {
      startY: state.y,
      head: [['Type', 'Title', 'Description']],
      body: story.highlights.map(h => [
        h.type.toUpperCase(),
        h.title,
        h.description,
      ]),
      styles: { fontSize: 9, overflow: 'linebreak' },
      headStyles: { fillColor: [80, 130, 60] },
      margin: { left: MARGIN, right: MARGIN },
    });
    state.y = (doc as any).lastAutoTable.finalY + SECTION_GAP;
  }

  // Narrative sections
  if (story.narrative?.length) {
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    checkBreak(doc, state, 14);
    doc.text('Narrative', MARGIN, state.y);
    state.y += LINE;
    story.narrative.forEach(section => {
      checkBreak(doc, state, 14);
      doc.setFontSize(10);
      doc.setFont('helvetica', 'bold');
      doc.text(section.title, MARGIN, state.y);
      state.y += LINE;
      doc.setFont('helvetica', 'normal');
      bodyText(doc, state, section.content);
      state.y += 4;
    });
    state.y += SECTION_GAP;
  }

  // Key events timeline
  if (story.timeline?.length) {
    checkBreak(doc, state, 14);
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.text('Key Events Timeline', MARGIN, state.y);
    state.y += LINE;
    autoTable(doc, {
      startY: state.y,
      head: [['Time', 'Type', 'Event', 'Description']],
      body: story.timeline
        .slice()
        .sort((a, b) => a.timestamp - b.timestamp)
        .map(e => [
          fmtTs(e.timestamp),
          e.type.toUpperCase(),
          e.title,
          e.description,
        ]),
      styles: { fontSize: 8, overflow: 'linebreak' },
      headStyles: { fillColor: [80, 130, 60] },
      margin: { left: MARGIN, right: MARGIN },
    });
    state.y = (doc as any).lastAutoTable.finalY + SECTION_GAP;
  }
}

function renderNetwork(
  doc: jsPDF,
  state: DocState,
  nodes: GraphNode[],
  stats: NetworkStats
) {
  doc.addPage();
  state.y = 20;
  sectionTitle(doc, state, '4. Network Topology');

  // Stats summary
  kv(doc, state, 'Total Nodes:', stats.totalNodes.toString());
  kv(doc, state, 'Total Connections:', stats.totalEdges.toString());
  kv(doc, state, 'Total Packets:', stats.totalPackets.toLocaleString());
  kv(doc, state, 'Total Bytes:', fmtBytes(stats.totalBytes));
  state.y += 4;

  // Protocol breakdown
  if (Object.keys(stats.protocolBreakdown).length) {
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    checkBreak(doc, state, 14);
    doc.text('Protocol Breakdown', MARGIN, state.y);
    state.y += LINE;
    autoTable(doc, {
      startY: state.y,
      head: [['Protocol', 'Connections']],
      body: Object.entries(stats.protocolBreakdown)
        .sort(([, a], [, b]) => b - a)
        .map(([proto, count]) => [proto, count.toLocaleString()]),
      styles: { fontSize: 9 },
      headStyles: { fillColor: [30, 80, 160] },
      tableWidth: 80,
      margin: { left: MARGIN, right: MARGIN },
    });
    state.y = (doc as any).lastAutoTable.finalY + SECTION_GAP;
  }

  // Node inventory
  if (nodes.length) {
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    checkBreak(doc, state, 14);
    doc.text('Node Inventory', MARGIN, state.y);
    state.y += LINE;
    autoTable(doc, {
      startY: state.y,
      head: [['IP Address', 'Type', 'Role', 'Connections', 'Bytes Sent', 'Bytes Received']],
      body: nodes
        .slice()
        .sort((a, b) => b.data.totalBytes - a.data.totalBytes)
        .map(n => [
          n.data.ip,
          n.data.nodeType,
          n.data.role,
          n.data.connections.toString(),
          fmtBytes(n.data.bytesSent),
          fmtBytes(n.data.bytesReceived),
        ]),
      styles: { fontSize: 8, overflow: 'linebreak' },
      headStyles: { fillColor: [30, 80, 160] },
      margin: { left: MARGIN, right: MARGIN },
    });
    state.y = (doc as any).lastAutoTable.finalY + SECTION_GAP;
  }
}

// ─── Main export ─────────────────────────────────────────────────────────────

export async function generateAnalysisReport(
  data: AnalysisSummary,
  fileId: string,
  onProgress?: (message: string) => void
) {
  const notify = (msg: string) => onProgress?.(msg);

  // Fetch data from all tabs in parallel where possible
  notify('Fetching conversations...');
  let conversations: Conversation[] = [];
  try {
    const resp = await conversationService.getConversations(fileId, 1, 10000);
    conversations = resp.data;
  } catch {
    // Skip conversations section gracefully
  }

  notify('Generating story narrative...');
  let story: Story | null = null;
  try {
    story = await storyService.generateStory(fileId);
  } catch {
    // Skip story section gracefully
  }

  notify('Building network graph...');
  let nodes: GraphNode[] = [];
  let stats: NetworkStats = { totalNodes: 0, totalEdges: 0, totalPackets: 0, totalBytes: 0, protocolBreakdown: {} };
  try {
    const graphData = networkService.buildNetworkGraph(conversations, data);
    nodes = graphData.nodes;
    stats = graphData.stats;
  } catch {
    // Skip network section gracefully
  }

  notify('Generating PDF...');
  const doc = new jsPDF();
  const state: DocState = { y: 20 };

  // ── Cover page ──────────────────────────────────────────────────────────
  const pw = pageWidth(doc);
  doc.setFontSize(22);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(20, 60, 130);
  doc.text('Network Traffic Analysis Report', pw / 2, 60, { align: 'center' });

  doc.setFontSize(12);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(80, 80, 80);
  doc.text(data.fileName ?? fileId ?? '', pw / 2, 74, { align: 'center' });

  doc.setFontSize(10);
  doc.text(`Generated: ${new Date().toLocaleString()}`, pw / 2, 84, { align: 'center' });

  doc.setDrawColor(30, 80, 160);
  doc.setLineWidth(0.5);
  doc.line(MARGIN, 90, pw - MARGIN, 90);

  // Table of contents
  doc.setTextColor(0, 0, 0);
  doc.setFontSize(12);
  doc.setFont('helvetica', 'bold');
  doc.text('Contents', MARGIN, 105);
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(10);
  const toc = [
    '1. Overview — file info, packet summary, protocol distribution, Five W\'s analysis',
    '2. Conversations — full conversation table',
    '3. Story — AI-generated narrative, highlights, and key events',
    '4. Network Topology — node inventory and protocol breakdown',
  ];
  toc.forEach((line, i) => {
    doc.text(line, MARGIN, 118 + i * 10);
  });

  doc.addPage();
  state.y = 20;

  // ── Sections ────────────────────────────────────────────────────────────
  renderOverview(doc, state, data, fileId);
  renderConversations(doc, state, conversations);
  if (story) renderStory(doc, state, story);
  renderNetwork(doc, state, nodes, stats);

  addFooters(doc);

  doc.save(`report-${data.fileName ?? fileId}.pdf`);
}
