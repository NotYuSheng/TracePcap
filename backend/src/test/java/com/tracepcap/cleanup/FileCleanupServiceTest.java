package com.tracepcap.cleanup;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.tracepcap.analysis.spi.PacketPartitions;
import com.tracepcap.common.settings.EditablePolicy;
import com.tracepcap.common.settings.RuntimePolicy;
import com.tracepcap.config.CleanupProperties;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.entity.FileEntity.FileSource;
import com.tracepcap.file.repository.FileRepository;
import com.tracepcap.file.service.FileService;
import com.tracepcap.monitor.repository.NetworkSnapshotRepository;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Retention: an analysis capture kept with a monitored network is not deleted with the others. */
class FileCleanupServiceTest {

  private final FileRepository files = mock(FileRepository.class);
  private final FileService fileService = mock(FileService.class);
  private final RuntimePolicy policy = mock(RuntimePolicy.class);
  private final NetworkSnapshotRepository snapshots = mock(NetworkSnapshotRepository.class);
  private FileCleanupService service;

  private final FileEntity loose = file();
  private final FileEntity kept = file();

  private static FileEntity file() {
    FileEntity f = new FileEntity();
    f.setId(UUID.randomUUID());
    f.setFileName("capture.pcap");
    return f;
  }

  @BeforeEach
  void setUp() {
    CleanupProperties props = new CleanupProperties();
    props.setEnabled(true);
    service =
        new FileCleanupService(
            files, fileService, props, mock(PacketPartitions.class), snapshots, policy);
    when(policy.getInt(EditablePolicy.FILE_RETENTION_HOURS)).thenReturn(12);
    when(files.findBySourceAndUploadedAtBefore(eq(FileSource.ANALYSIS), any()))
        .thenReturn(List.of(loose, kept));
    when(snapshots.findAllMemberships())
        .thenReturn(List.<Object[]>of(new Object[] {UUID.randomUUID(), kept.getId()}));
  }

  @Test
  void deletesExpiredAnalysisCaptures_butNotOnesKeptWithANetwork() {
    when(policy.getInt(EditablePolicy.MONITOR_FILE_RETENTION_HOURS)).thenReturn(0);
    service.cleanupExpiredFiles();
    verify(fileService).deleteFile(loose.getId());
    verify(fileService, never()).deleteFile(kept.getId());
  }

  @Test
  void aCaptureKeptWithANetwork_followsTheMonitorRetention() {
    when(policy.getInt(EditablePolicy.MONITOR_FILE_RETENTION_HOURS)).thenReturn(24);
    when(files.findBySourceAndUploadedAtBefore(eq(FileSource.MONITOR), any()))
        .thenReturn(List.of());
    service.cleanupExpiredFiles();
    verify(fileService).deleteFile(kept.getId());
  }
}
