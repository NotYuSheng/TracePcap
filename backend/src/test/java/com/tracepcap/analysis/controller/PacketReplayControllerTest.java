package com.tracepcap.analysis.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.tracepcap.analysis.dto.replay.ReplayPacket;
import com.tracepcap.analysis.repository.PacketRepository;
import com.tracepcap.common.exception.ResourceNotFoundException;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.repository.FileRepository;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/** {@code GET /files/{id}/packets}: pages by frame number, seeking by time, pruned captures. */
class PacketReplayControllerTest {

  private final UUID fileId = UUID.randomUUID();
  private final PacketRepository packets = mock(PacketRepository.class);
  private final FileRepository files = mock(FileRepository.class);
  private final PacketReplayController controller = new PacketReplayController(packets, files);

  private ReplayPacket packet(long n) {
    return new ReplayPacket(n, LocalDateTime.of(2026, 11, 14, 9, 0), "10.0.0.1", 1234, "10.0.0.2", 443, "TCP", 60, UUID.randomUUID(), "[SYN]");
  }

  private void file(LocalDateTime prunedAt) {
    FileEntity f = new FileEntity();
    f.setId(fileId);
    f.setPacketsPrunedAt(prunedAt);
    when(files.findById(fileId)).thenReturn(Optional.of(f));
  }

  @Test
  void pageIsAFrameNumberRange() {
    file(null);
    when(packets.countByFile_Id(fileId)).thenReturn(4500L);
    when(packets.findReplayPage(fileId, 2001, 4000)).thenReturn(List.of(packet(2001)));

    var r = controller.packets(fileId, 2, 2000, null);

    assertThat(r.getPage()).isEqualTo(2);
    assertThat(r.getTotal()).isEqualTo(4500);
    assertThat(r.getTotalPages()).isEqualTo(3);
    assertThat(r.getData()).extracting(ReplayPacket::number).containsExactly(2001L);
  }

  @Test
  void atSeeksToThePageHoldingThatTime() {
    file(null);
    var at = LocalDateTime.of(2026, 11, 14, 9, 5);
    when(packets.countByFile_Id(fileId)).thenReturn(4500L);
    when(packets.findFirstPacketNumberAtOrAfter(fileId, at)).thenReturn(4321L);
    when(packets.findReplayPage(fileId, 4001, 6000)).thenReturn(List.of(packet(4321)));

    var r = controller.packets(fileId, 1, 2000, at);

    assertThat(r.getPage()).isEqualTo(3);
    assertThat(r.getData()).hasSize(1);
  }

  @Test
  void atPastTheEndGivesTheLastPage() {
    file(null);
    var at = LocalDateTime.of(2030, 1, 1, 0, 0);
    when(packets.countByFile_Id(fileId)).thenReturn(4500L);
    when(packets.findFirstPacketNumberAtOrAfter(fileId, at)).thenReturn(null);

    assertThat(controller.packets(fileId, 1, 2000, at).getPage()).isEqualTo(3);
  }

  @Test
  void pagePastTheEndIsEmpty_withoutQuerying() {
    file(null);
    when(packets.countByFile_Id(fileId)).thenReturn(10L);

    assertThat(controller.packets(fileId, 2, 2000, null).getData()).isEmpty();
    verify(packets, never()).findReplayPage(org.mockito.ArgumentMatchers.any(), anyLong(), anyLong());
  }

  @Test
  void prunedOrMissingCapture_is404() {
    file(LocalDateTime.now());
    assertThatThrownBy(() -> controller.packets(fileId, 1, 2000, null)).isInstanceOf(ResourceNotFoundException.class);

    UUID other = UUID.randomUUID();
    when(files.findById(other)).thenReturn(Optional.empty());
    assertThatThrownBy(() -> controller.packets(other, 1, 2000, null)).isInstanceOf(ResourceNotFoundException.class);
  }
}
