package com.tracepcap.file.service;

import com.tracepcap.common.exception.StorageException;
import com.tracepcap.config.MinioConfig;
import io.minio.*;
import io.minio.http.Method;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.concurrent.TimeUnit;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

/** Implementation of StorageService using MinIO */
@Slf4j
@Service
@RequiredArgsConstructor
public class StorageServiceImpl implements StorageService {

  private final MinioClient minioClient;
  private final MinioConfig minioConfig;

  @Override
  public String uploadFile(MultipartFile file, String fileName) {
    try {
      // Ensure bucket exists
      ensureBucketExists();

      // Upload file
      minioClient.putObject(
          PutObjectArgs.builder().bucket(minioConfig.getBucket()).object(fileName).stream(
                  file.getInputStream(), file.getSize(), -1)
              .contentType(file.getContentType())
              .build());

      log.info("Successfully uploaded file: {} to MinIO", fileName);
      return fileName;

    } catch (Exception e) {
      log.error("Failed to upload file: {}", fileName, e);
      throw new StorageException("Failed to upload file to storage", e);
    }
  }

  @Override
  public InputStream downloadFile(String fileName) {
    try {
      return minioClient.getObject(
          GetObjectArgs.builder().bucket(minioConfig.getBucket()).object(fileName).build());
    } catch (Exception e) {
      log.error("Failed to download file: {}", fileName, e);
      throw new StorageException("Failed to download file from storage", e);
    }
  }

  @Override
  public void deleteFile(String fileName) {
    try {
      minioClient.removeObject(
          RemoveObjectArgs.builder().bucket(minioConfig.getBucket()).object(fileName).build());
      log.info("Successfully deleted file: {} from MinIO", fileName);
    } catch (Exception e) {
      log.error("Failed to delete file: {}", fileName, e);
      throw new StorageException("Failed to delete file from storage", e);
    }
  }

  @Override
  public boolean fileExists(String fileName) {
    try {
      minioClient.statObject(
          StatObjectArgs.builder().bucket(minioConfig.getBucket()).object(fileName).build());
      return true;
    } catch (Exception e) {
      return false;
    }
  }

  @Override
  public String getPresignedUrl(String fileName, int expiry) {
    try {
      return minioClient.getPresignedObjectUrl(
          GetPresignedObjectUrlArgs.builder()
              .method(Method.GET)
              .bucket(minioConfig.getBucket())
              .object(fileName)
              .expiry(expiry, TimeUnit.SECONDS)
              .build());
    } catch (Exception e) {
      log.error("Failed to generate presigned URL for file: {}", fileName, e);
      throw new StorageException("Failed to generate download URL", e);
    }
  }

  @Override
  public void downloadFileToLocal(String fileName, File targetFile) {
    try {
      log.debug("Downloading file from MinIO: {} to {}", fileName, targetFile.getAbsolutePath());

      try (InputStream stream = downloadFile(fileName);
          FileOutputStream outputStream = new FileOutputStream(targetFile)) {

        byte[] buffer = new byte[8192];
        int bytesRead;
        while ((bytesRead = stream.read(buffer)) != -1) {
          outputStream.write(buffer, 0, bytesRead);
        }
      }

      log.debug("Successfully downloaded file to: {}", targetFile.getAbsolutePath());
    } catch (Exception e) {
      log.error("Failed to download file to local: {}", fileName, e);
      throw new StorageException("Failed to download file to local storage", e);
    }
  }

  /** Ensure the bucket exists, create if it doesn't */
  private void ensureBucketExists() {
    try {
      boolean exists =
          minioClient.bucketExists(
              BucketExistsArgs.builder().bucket(minioConfig.getBucket()).build());

      if (!exists) {
        minioClient.makeBucket(MakeBucketArgs.builder().bucket(minioConfig.getBucket()).build());
        log.info("Created MinIO bucket: {}", minioConfig.getBucket());
      }
    } catch (Exception e) {
      log.error("Failed to check/create bucket: {}", minioConfig.getBucket(), e);
      throw new StorageException("Failed to initialize storage bucket", e);
    }
  }
}
