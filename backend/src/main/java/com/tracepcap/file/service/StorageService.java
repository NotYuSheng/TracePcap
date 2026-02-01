package com.tracepcap.file.service;

import org.springframework.web.multipart.MultipartFile;

import java.io.InputStream;

/**
 * Service interface for file storage operations (MinIO)
 */
public interface StorageService {

    /**
     * Upload a file to storage
     *
     * @param file     the file to upload
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
     * @param expiry   expiry time in seconds
     * @return pre-signed URL
     */
    String getPresignedUrl(String fileName, int expiry);

    /**
     * Download a file from storage to a local file
     *
     * @param fileName   the name of the file in storage
     * @param targetFile the local file to write to
     */
    void downloadFileToLocal(String fileName, java.io.File targetFile);
}
