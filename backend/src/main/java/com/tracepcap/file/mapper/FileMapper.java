package com.tracepcap.file.mapper;

import com.tracepcap.file.dto.FileMetadataDto;
import com.tracepcap.file.dto.FileUploadResponse;
import com.tracepcap.file.entity.FileEntity;
import org.springframework.stereotype.Component;

/** Mapper for converting between FileEntity and DTOs */
@Component
public class FileMapper {

  public FileUploadResponse toUploadResponse(FileEntity entity) {
    return FileUploadResponse.builder()
        .fileId(entity.getId().toString())
        .fileName(entity.getFileName())
        .fileSize(entity.getFileSize())
        .uploadedAt(entity.getUploadedAt())
        .status(entity.getStatus().name().toLowerCase())
        .storageLocation("s3://tracepcap-files/" + entity.getMinioPath())
        .build();
  }

  public FileMetadataDto toMetadataDto(FileEntity entity) {
    return FileMetadataDto.builder()
        .fileId(entity.getId().toString())
        .fileName(entity.getFileName())
        .fileSize(entity.getFileSize())
        .uploadedAt(entity.getUploadedAt())
        .status(entity.getStatus().name().toLowerCase())
        .packetCount(entity.getPacketCount())
        .duration(entity.getDuration())
        .startTime(entity.getStartTime())
        .endTime(entity.getEndTime())
        .build();
  }
}
