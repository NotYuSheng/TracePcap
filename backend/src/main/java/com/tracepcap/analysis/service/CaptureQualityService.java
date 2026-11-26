package com.tracepcap.analysis.service;

import com.tracepcap.analysis.dto.CaptureQualityResponse;
import com.tracepcap.analysis.dto.CaptureQualityResponse.Note;
import com.tracepcap.analysis.entity.CaptureStatsEntity;
import com.tracepcap.analysis.repository.CaptureStatsRepository;
import com.tracepcap.analysis.repository.ConversationRepository;
import com.tracepcap.analysis.spi.CaptureQualityLookup;
import com.tracepcap.common.exception.ResourceNotFoundException;
import com.tracepcap.file.repository.FileRepository;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Says how complete a capture is (#1268): from TracePcap's own conversations (connections already
 * open when the capture began) and Suricata's counters (gaps, undecodable packets, sessions it
 * stopped inspecting). The point is honesty about absences: no alert in a stream with gaps is not
 * the same as a clean stream.
 */
@Service
@RequiredArgsConstructor
public class CaptureQualityService implements CaptureQualityLookup {

  /** Above this share of TCP conversations without a handshake, it's worth saying. */
  static final double MIDSTREAM_SHARE = 0.10;

  private final FileRepository files;
  private final ConversationRepository conversations;
  private final CaptureStatsRepository stats;

  @Transactional(readOnly = true)
  public CaptureQualityResponse forFile(UUID fileId) {
    var file = files.findById(fileId)
        .orElseThrow(() -> new ResourceNotFoundException("File not found: " + fileId));
    Long filePackets = file.getPacketCount() == null ? null : file.getPacketCount().longValue();
    long tcp = conversations.countTcp(fileId);
    long noHandshake = conversations.countTcpWithoutHandshake(fileId);
    CaptureStatsEntity s = stats.findById(fileId).orElse(null);
    List<Note> notes = notes(tcp, noHandshake, s, filePackets);
    return CaptureQualityResponse.builder()
        .verdict(notes.isEmpty() ? "complete" : "notes")
        .notes(notes)
        .tcpConversations(tcp)
        .tcpWithoutHandshake(noHandshake)
        .packets(s == null ? null : s.getPackets())
        .invalidPackets(s == null ? null : s.getInvalidPackets())
        .tcpSessions(s == null ? null : s.getTcpSessions())
        .reassemblyGaps(s == null ? null : s.getReassemblyGaps())
        .streamDepthReached(s == null ? null : s.getStreamDepthReached())
        .memcapDrops(s == null ? null : s.getMemcapDrops())
        .build();
  }

  @Override
  @Transactional(readOnly = true)
  public List<QualityNote> qualityNotes(UUID fileId) {
    return forFile(fileId).getNotes().stream()
        .map(n -> new QualityNote(n.getKind(), n.getLevel(), n.getText()))
        .toList();
  }

  /** Below this share of the file's packets read by Suricata, its alerts are incomplete. */
  static final double SURICATA_READ_SHARE = 0.9;

  /** As {@link #notes(long, long, CaptureStatsEntity, Long)} without the file's packet count. */
  static List<Note> notes(long tcp, long noHandshake, CaptureStatsEntity s) {
    return notes(tcp, noHandshake, s, null);
  }

  /** The notes, most consequential first. Package-private for tests. */
  static List<Note> notes(long tcp, long noHandshake, CaptureStatsEntity s, Long filePackets) {
    List<Note> out = new ArrayList<>();
    // Suricata reads captures through libpcap, which can't read a pcapng mixing link types (an
    // Ethernet and a Linux-cooked interface, say): it then decodes nothing and still succeeds, so
    // "no alerts" would read as clean.
    if (s != null && s.getPackets() != null && filePackets != null && filePackets > 0
        && s.getPackets() < SURICATA_READ_SHARE * filePackets) {
      out.add(note("suricata-unread", "warning", s.getPackets() == 0
          ? "Suricata couldn't read this capture (0 of " + filePackets + " packets), so it has no IDS"
              + " alerts at all: their absence doesn't mean the traffic is clean. A capture that mixes"
              + " link types (several interfaces in one pcapng) does this."
          : "Suricata read only " + s.getPackets() + " of " + filePackets + " packets, so IDS alerts"
              + " for the rest are missing. A capture that mixes link types (several interfaces in one"
              + " pcapng) does this."));
    }
    if (s != null && pos(s.getReassemblyGaps())) {
      out.add(note("gaps", "warning", s.getReassemblyGaps() + " gap" + plural(s.getReassemblyGaps())
          + " in TCP streams: packets are missing from the capture, so alerts and files in those"
          + " streams can be missed."));
    }
    if (s != null && pos(s.getMemcapDrops())) {
      out.add(note("memcap", "warning", "Suricata ran out of memory " + s.getMemcapDrops() + " time"
          + plural(s.getMemcapDrops()) + " on this capture, so some traffic wasn't inspected."));
    }
    // Every connection mid-stream is the case that needs this most (a capture that began after its
    // sessions did). Captures analysed before connection outcomes existed (#1233) have no transport
    // either, so they're never counted as TCP here.
    if (tcp > 0 && noHandshake > 0 && (double) noHandshake / tcp > MIDSTREAM_SHARE) {
      out.add(note("midstream", "info", noHandshake + " of " + tcp + " TCP connections ("
          + Math.round(100.0 * noHandshake / tcp) + "%) were already open when the capture began:"
          + " how they started, and which side opened them, isn't in it."));
    }
    if (s != null && pos(s.getInvalidPackets())) {
      out.add(note("invalid", "info", s.getInvalidPackets() + " packet" + plural(s.getInvalidPackets())
          + " couldn't be decoded (truncated or malformed)."));
    }
    if (s != null && pos(s.getStreamDepthReached())) {
      out.add(note("depth", "info", s.getStreamDepthReached() + " TCP session"
          + plural(s.getStreamDepthReached()) + " ran past the first 1 MiB Suricata inspects in each:"
          + " an alert later in those sessions can be missed."));
    }
    return out;
  }

  private static boolean pos(Long v) {
    return v != null && v > 0;
  }

  private static String plural(long n) {
    return n == 1 ? "" : "s";
  }

  private static Note note(String kind, String level, String text) {
    return Note.builder().kind(kind).level(level).text(text).build();
  }
}
