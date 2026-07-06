package com.tracepcap.file.mapper;

import com.tracepcap.file.dto.FileMetadataDto;
import com.tracepcap.file.dto.FileUploadResponse;
import com.tracepcap.file.entity.FileEntity;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** Mapper for converting between FileEntity and DTOs */
@Component
public class FileMapper {

  // Global Suricata kill-switch (SURICATA_ENABLED). When false, Suricata never ran regardless of
  // the per-file flag, so the DTO must report the effective state — matching ReportService and
  // AnalysisService — otherwise the UI would not flag such files as partial. See AnalysisService.
  @Value("${tracepcap.suricata.enabled:true}")
  private boolean suricataEnabled;

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
        .source(entity.getSource() != null ? entity.getSource().name() : null)
        .enableNdpi(entity.isEnableNdpi())
        .enableSuricata(suricataEnabled && entity.isEnableSuricata())
        .enableFileExtraction(entity.isEnableFileExtraction())
        .build();
  }
}
