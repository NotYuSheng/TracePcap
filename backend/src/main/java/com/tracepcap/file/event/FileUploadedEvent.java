package com.tracepcap.file.event;

import java.util.UUID;
import lombok.Getter;
import org.springframework.context.ApplicationEvent;

/** Event published when a file is successfully uploaded */
@Getter
public class FileUploadedEvent extends ApplicationEvent {

  private final UUID fileId;

  public FileUploadedEvent(Object source, UUID fileId) {
    super(source);
    this.fileId = fileId;
  }
}
