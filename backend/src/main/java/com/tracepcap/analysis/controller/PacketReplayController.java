package com.tracepcap.analysis.controller;

import com.tracepcap.analysis.dto.replay.ReplayPacket;
import com.tracepcap.analysis.repository.PacketRepository;
import com.tracepcap.common.dto.PagedResponse;
import com.tracepcap.common.exception.ResourceNotFoundException;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.repository.FileRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** A capture's packets in order, headers only: what the network graph's packet replay plays. */
@RestController
@RequestMapping("/files")
@RequiredArgsConstructor
@Validated
@Tag(name = "Packet Replay", description = "A capture's packets in capture order, for replaying them on the network graph")
public class PacketReplayController {

  static final int DEFAULT_PAGE_SIZE = 2000;
  static final int MAX_PAGE_SIZE = 5000;

  private final PacketRepository packets;
  private final FileRepository files;

  @GetMapping("/{fileId}/packets")
  @Transactional(readOnly = true)
  @Operation(
      summary = "A capture's packets, in capture order",
      description =
          "One page of packets, headers only: frame number, time, addresses and ports, protocol,"
              + " size, conversation and the dissector's summary. Pages run in frame order. With"
              + " `at`, the page returned is the one holding the first packet captured at or after"
              + " that time (its number is in `page`), so a replay can start anywhere. 404 when the"
              + " capture's packets were pruned.")
  public PagedResponse<ReplayPacket> packets(
      @PathVariable UUID fileId,
      @RequestParam(defaultValue = "1") @Min(1) int page,
      @RequestParam(defaultValue = "" + DEFAULT_PAGE_SIZE) @Min(1) @Max(MAX_PAGE_SIZE) int pageSize,
      @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime at) {
    FileEntity file =
        files.findById(fileId).orElseThrow(() -> new ResourceNotFoundException("File not found: " + fileId));
    if (file.getPacketsPrunedAt() != null) {
      throw new ResourceNotFoundException("The packets of this capture were pruned: it can't be replayed");
    }
    long total = packets.countByFile_Id(fileId);
    if (at != null) {
      Long first = packets.findFirstPacketNumberAtOrAfter(fileId, at);
      // Past the last packet: the last page.
      long number = first != null ? first : Math.max(1, total);
      page = (int) ((number - 1) / pageSize) + 1;
    }
    long from = (long) (page - 1) * pageSize + 1;
    List<ReplayPacket> data = from > total ? List.of() : packets.findReplayPage(fileId, from, from + pageSize - 1);
    return PagedResponse.of(data, total, page, pageSize);
  }
}
