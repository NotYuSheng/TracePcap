package com.tracepcap.file.service;

import java.io.InputStream;
import java.util.List;
import java.util.UUID;
import org.springframework.web.multipart.MultipartFile;

/** Service interface for file storage operations (MinIO) */
public interface StorageService {

  /** Root of everything extracted from captures; each file's objects sit under its own id. */
  String EXTRACTED_ROOT = "extracted/";

  /**
   * The prefix holding everything extracted from a file. Ends in a slash so one id can never match
   * another that merely starts with it.
   *
   * @param fileId the file the content was extracted from
   * @return the storage prefix
   */
  static String extractedPrefix(UUID fileId) {
    return EXTRACTED_ROOT + fileId + "/";
  }

  /**
   * Upload a file to storage
   *
   * @param file the file to upload
   * @param fileName the name to save the file as
   * @return the storage path
   */
  String uploadFile(MultipartFile file, String fileName);

  /**
   * Download a file from storage
   *
   * @param fileName the name of the file
   * @return input stream of the file
   */
  InputStream downloadFile(String fileName);

  /**
   * Delete a file from storage
   *
   * @param fileName the name of the file to delete
   */
  void deleteFile(String fileName);

  /**
   * Delete every object under a prefix
   *
   * @param prefix the prefix to delete; must end in a slash, so a blank or partial value can't
   *     match more than one folder
   * @return the number of objects deleted
   */
  int deleteByPrefix(String prefix);

  /**
   * List the folders directly under a prefix, without descending into them
   *
   * @param prefix the prefix to list; must end in a slash
   * @return the folder names, without the prefix or a trailing slash
   */
  List<String> listFolders(String prefix);

  /**
   * Check if a file exists in storage
   *
   * @param fileName the name of the file
   * @return true if file exists, false otherwise
   */
  boolean fileExists(String fileName);

  /**
   * Get a pre-signed URL for file download
   *
   * @param fileName the name of the file
   * @param expiry expiry time in seconds
   * @return pre-signed URL
   */
  String getPresignedUrl(String fileName, int expiry);

  /**
   * Download a file from storage to a local file
   *
   * @param fileName the name of the file in storage
   * @param targetFile the local file to write to
   */
  void downloadFileToLocal(String fileName, java.io.File targetFile);

  /**
   * Upload raw bytes to storage
   *
   * @param data the bytes to upload
   * @param path the destination path in storage
   * @param contentType MIME type of the content
   * @return the storage path
   */
  String uploadBytes(byte[] data, String path, String contentType);

  /**
   * Upload a local file to storage via streaming (avoids loading the whole file into memory).
   *
   * @param source the local file to upload
   * @param path the destination path in storage
   * @param contentType MIME type of the content
   * @return the storage path
   */
  String uploadFile(java.io.File source, String path, String contentType);
}
