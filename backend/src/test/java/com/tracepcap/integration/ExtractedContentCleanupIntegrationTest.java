package com.tracepcap.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.tracepcap.cleanup.OrphanedExtractedContentSweeper;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.repository.FileRepository;
import com.tracepcap.file.service.FileService;
import com.tracepcap.file.service.StorageService;
import java.time.LocalDateTime;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Verifies that deleting a file removes what was extracted from it (#855), against real MinIO.
 *
 * <p>Real storage rather than a mock because the bug lived in what the bucket still held
 * afterwards. {@code removeObjects} is also lazy, so a mock would pass even if nothing were ever
 * deleted.
 */
@SpringBootTest
@Testcontainers
class ExtractedContentCleanupIntegrationTest {

  @Container
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(DockerImageName.parse("postgres:15-alpine"));

  // Chainguard, not Docker Hub or quay.io: see PacketPartitionIntegrationTest.
  @Container
  static final GenericContainer<?> MINIO =
      new GenericContainer<>(DockerImageName.parse("cgr.dev/chainguard/minio:latest"))
          .withEnv("MINIO_ROOT_USER", "minioadmin")
          .withEnv("MINIO_ROOT_PASSWORD", "minioadmin")
          .withCommand("server", "/data")
          .withExposedPorts(9000)
          .waitingFor(Wait.forHttp("/minio/health/ready").forPort(9000));

  @DynamicPropertySource
  static void properties(DynamicPropertyRegistry registry) {
    registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
    registry.add("spring.datasource.username", POSTGRES::getUsername);
    registry.add("spring.datasource.password", POSTGRES::getPassword);
    registry.add(
        "minio.endpoint", () -> "http://" + MINIO.getHost() + ":" + MINIO.getMappedPort(9000));
    registry.add("minio.access-key", () -> "minioadmin");
    registry.add("minio.secret-key", () -> "minioadmin");
  }

  @Autowired private FileService fileService;
  @Autowired private FileRepository fileRepository;
  @Autowired private StorageService storageService;
  @Autowired private OrphanedExtractedContentSweeper sweeper;

  @Test
  void deletingAFile_removesItsExtractedContent() {
    UUID fileId = insertFile();
    String first = putExtracted(fileId, "report.pdf");
    String second = putExtracted(fileId, "image.png");

    fileService.deleteFile(fileId);

    assertThat(storageService.fileExists(first)).isFalse();
    assertThat(storageService.fileExists(second)).isFalse();
  }

  @Test
  void deletingAFile_leavesOtherFilesExtractedContentAlone() {
    UUID deleted = insertFile();
    UUID kept = insertFile();
    putExtracted(deleted, "report.pdf");
    String keptObject = putExtracted(kept, "report.pdf");

    fileService.deleteFile(deleted);

    assertThat(storageService.fileExists(keptObject)).isTrue();
  }

  @Test
  void deletingAFileWithNoExtractedContent_succeeds() {
    UUID fileId = insertFile();

    fileService.deleteFile(fileId);

    assertThat(fileRepository.existsById(fileId)).isFalse();
  }

  @Test
  void sweep_removesContentWhoseFileIsGone() {
    String orphan = putExtracted(UUID.randomUUID(), "left-behind.pdf");

    sweeper.sweep();

    assertThat(storageService.fileExists(orphan)).isFalse();
  }

  @Test
  void sweep_keepsContentOfFilesThatStillExist() {
    UUID fileId = insertFile();
    String object = putExtracted(fileId, "report.pdf");

    sweeper.sweep();

    assertThat(storageService.fileExists(object)).isTrue();
  }

  @Test
  void sweep_ignoresFoldersThatAreNotFileIds() {
    String unexpected = StorageService.EXTRACTED_ROOT + "not-a-file-id/keep.txt";
    storageService.uploadBytes(new byte[] {1}, unexpected, "text/plain");

    sweeper.sweep();

    assertThat(storageService.fileExists(unexpected)).isTrue();
  }

  @Test
  void deleteByPrefix_refusesAnythingButAFolder() {
    // A blank prefix would otherwise match the whole bucket, including every original capture.
    assertThatThrownBy(() -> storageService.deleteByPrefix(""))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> storageService.deleteByPrefix("extracted"))
        .isInstanceOf(IllegalArgumentException.class);
  }

  private UUID insertFile() {
    UUID id = UUID.randomUUID();
    String path = "captures/" + id + ".pcap";
    storageService.uploadBytes(new byte[] {1}, path, "application/vnd.tcpdump.pcap");
    fileRepository.save(
        FileEntity.builder()
            .id(id)
            .fileName(id + ".pcap")
            .fileSize(1L)
            .minioPath(path)
            .uploadedAt(LocalDateTime.now())
            .status(FileEntity.FileStatus.COMPLETED)
            .build());
    return id;
  }

  private String putExtracted(UUID fileId, String name) {
    String path = StorageService.extractedPrefix(fileId) + UUID.randomUUID() + "/" + name;
    storageService.uploadBytes(new byte[] {1, 2, 3}, path, "application/octet-stream");
    return path;
  }
}
