package com.tracepcap.common.exception;

import java.util.UUID;
import lombok.Getter;

/** Thrown when an uploaded file matches the hash of an existing file */
@Getter
public class DuplicateFileException extends RuntimeException {

  private final UUID existingFileId;

  public DuplicateFileException(UUID existingFileId) {
    super("This file has already been uploaded");
    this.existingFileId = existingFileId;
  }
}
