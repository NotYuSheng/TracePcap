package com.tracepcap.file.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.entity.FileEntity.FileSource;
import com.tracepcap.file.event.FileUploadedEvent;
import com.tracepcap.file.mapper.FileMapper;
import com.tracepcap.file.repository.FileRepository;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.SimpleTransactionStatus;
import org.springframework.web.multipart.MultipartFile;

/**
 * Upload and merge must hold a DB connection only for the insert and the event publish (#826).
 *
 * <p>Both methods used to be {@code @Transactional}, so a pooled connection was held through {@code
 * capinfos}, hashing, the MinIO upload and, for a merge, {@code mergecap}. Re-adding the annotation
 * would compile and pass every functional test, which is why the first test checks for the
 * annotation directly, in the same way as {@code AnalysisTransactionBoundaryTest}. The second test
 * checks that the narrowed boundary still covers the insert and the publish. The analysis trigger
 * is an {@code AFTER_COMMIT} listener, so publishing outside a transaction would quietly stop
 * analysis from ever starting.
 */
class FileUploadTransactionBoundaryTest {

  @Test
  void uploadAndMergeDoNotOpenAMethodWideTransaction() throws Exception {
    Method upload =
        FileServiceImpl.class.getMethod(
            "uploadFile",
            MultipartFile.class,
            boolean.class,
            boolean.class,
            boolean.class,
            FileSource.class);
    Method merge =
        FileServiceImpl.class.getMethod(
            "mergeFiles", List.class, String.class, boolean.class, boolean.class, boolean.class);

    for (Method m : List.of(upload, merge)) {
      assertThat(m.getAnnotation(Transactional.class))
          .as(
              "%s must not be @Transactional: it would hold a pooled connection across capinfos,"
                  + " MinIO and (for merge) mergecap. Use persistAndPublish instead (#826)",
              m.getName())
          .isNull();
    }
    assertThat(FileServiceImpl.class.getAnnotation(Transactional.class))
        .as("a class-level @Transactional would re-wrap both methods")
        .isNull();
  }

  @Test
  void storageRunsOutsideTheTransaction_insertAndPublishRunInsideIt() {
    RecordingTxManager tx = new RecordingTxManager();
    List<String> trace = new ArrayList<>();

    FileRepository repo = mock(FileRepository.class);
    StorageService storage = mock(StorageService.class);
    FileMapper mapper = mock(FileMapper.class);
    ApplicationEventPublisher publisher = mock(ApplicationEventPublisher.class);

    when(repo.findFirstByFileHashOrderByUploadedAtDesc(anyString()))
        .thenAnswer(
            inv -> {
              trace.add("hash-lookup tx=" + tx.active);
              return Optional.empty();
            });
    when(storage.uploadFile(any(MultipartFile.class), anyString()))
        .thenAnswer(
            inv -> {
              trace.add("minio tx=" + tx.active);
              return inv.getArgument(1);
            });
    when(repo.save(any(FileEntity.class)))
        .thenAnswer(
            inv -> {
              trace.add("save tx=" + tx.active);
              return inv.getArgument(0);
            });
    org.mockito.Mockito.doAnswer(
            inv -> {
              trace.add("publish tx=" + tx.active);
              return null;
            })
        .when(publisher)
        .publishEvent(any(FileUploadedEvent.class));

    // maxPackets = 0 disables the packet gate, so the test doesn't depend on capinfos being
    // installed. countPackets still runs, and is best-effort either way.
    FileServiceImpl service =
        new FileServiceImpl(repo, storage, mapper, publisher, tx, 1024 * 1024, 0, 0.5);

    service.uploadFile(
        new MockMultipartFile("file", "capture.pcap", "application/octet-stream", new byte[64]),
        false,
        false,
        false,
        FileSource.ANALYSIS);

    assertThat(trace)
        .containsExactly(
            "hash-lookup tx=false", "minio tx=false", "save tx=true", "publish tx=true");
    assertThat(tx.begun).as("exactly one short transaction").isEqualTo(1);
    assertThat(tx.committed).isEqualTo(1);

    InOrder order = inOrder(storage, repo, publisher);
    order.verify(storage).uploadFile(any(MultipartFile.class), anyString());
    order.verify(repo).save(any(FileEntity.class));
    order.verify(publisher).publishEvent(any(FileUploadedEvent.class));
  }

  @Test
  void losingTheDuplicateRace_is409WithTheWinnersId_andTheOrphanedObjectIsRemoved() {
    // Two identical uploads both pass the hash fast path, and the unique index (V44) rejects the
    // second insert. That must surface as the normal duplicate answer, not a 400 "Failed to upload
    // file", and the object this upload already put in MinIO must not be left behind.
    FileRepository repo = mock(FileRepository.class);
    StorageService storage = mock(StorageService.class);
    FileEntity winner = FileEntity.builder().id(java.util.UUID.randomUUID()).build();

    when(repo.findFirstByFileHashOrderByUploadedAtDesc(anyString()))
        .thenReturn(Optional.empty()) // fast path: the winner hasn't committed yet
        .thenReturn(Optional.of(winner)); // after the violation: it has
    when(storage.uploadFile(any(MultipartFile.class), anyString()))
        .thenAnswer(inv -> inv.getArgument(1));
    when(repo.save(any(FileEntity.class)))
        .thenThrow(
            new org.springframework.dao.DataIntegrityViolationException(
                "duplicate key value violates unique constraint \"uq_files_file_hash\""));

    FileServiceImpl service =
        new FileServiceImpl(
            repo,
            storage,
            mock(FileMapper.class),
            mock(ApplicationEventPublisher.class),
            new RecordingTxManager(),
            1024 * 1024,
            0,
            0.5);

    org.assertj.core.api.Assertions.assertThatThrownBy(
            () ->
                service.uploadFile(
                    new MockMultipartFile("file", "capture.pcap", "application/octet-stream", new byte[64]),
                    false,
                    false,
                    false,
                    FileSource.ANALYSIS))
        .isInstanceOfSatisfying(
            com.tracepcap.common.exception.DuplicateFileException.class,
            e -> assertThat(e.getExistingFileId()).isEqualTo(winner.getId()));
    org.mockito.Mockito.verify(storage).deleteFile(org.mockito.ArgumentMatchers.endsWith(".pcap"));
  }

  /** Tracks whether a transaction is open, without a datasource. */
  private static final class RecordingTxManager implements PlatformTransactionManager {
    boolean active;
    int begun;
    int committed;

    @Override
    public TransactionStatus getTransaction(TransactionDefinition definition) {
      active = true;
      begun++;
      return new SimpleTransactionStatus(true);
    }

    @Override
    public void commit(TransactionStatus status) {
      active = false;
      committed++;
    }

    @Override
    public void rollback(TransactionStatus status) {
      active = false;
    }
  }
}
