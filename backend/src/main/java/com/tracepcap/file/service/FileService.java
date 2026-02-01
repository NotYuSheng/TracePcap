package com.tracepcap.file.service;

import com.tracepcap.file.dto.FileMetadataDto;
import com.tracepcap.file.dto.FileUploadResponse;
import com.tracepcap.file.entity.FileEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.web.multipart.MultipartFile;

import java.io.InputStream;
import java.util.UUID;

/**
 * Service interface for file management operations
 */
public interface FileService {

    /**
     * Upload a PCAP file
     *
     * @param file the multipart file
     * @return upload response with file metadata
     */
    FileUploadResponse uploadFile(MultipartFile file);

    /**
     * Get file metadata by ID
     *
     * @param fileId the file ID
     * @return file metadata
     */
    FileMetadataDto getFileMetadata(UUID fileId);

    /**
     * Get all files with pagination
     *
     * @param pageable pagination information
     * @return page of file metadata
     */
    Page<FileMetadataDto> getAllFiles(Pageable pageable);

    /**
     * Download a file
     *
     * @param fileId the file ID
     * @return input stream of the file
     */
    InputStream downloadFile(UUID fileId);

    /**
     * Delete a file
     *
     * @param fileId the file ID
     */
    void deleteFile(UUID fileId);

    /**
     * Get file name by ID
     *
     * @param fileId the file ID
     * @return file name
     */
    String getFileName(UUID fileId);

    /**
     * Get file entity by ID
     *
     * @param fileId the file ID
     * @return file entity
     */
    FileEntity getFileById(UUID fileId);
}
