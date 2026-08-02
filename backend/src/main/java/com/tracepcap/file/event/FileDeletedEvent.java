package com.tracepcap.file.event;

import java.util.UUID;
import lombok.Getter;
import org.springframework.context.ApplicationEvent;

/**
 * Event published when a file has been deleted, after its row is gone.
 *
 * <p>Lets modules reclaim storage the FK cascade cannot reach — notably the file's {@code packets}
 * partition, which the cascade empties but cannot drop (#394). Announcing it keeps the dependency
 * pointing the right way: {@code file} would otherwise have to reach into {@code analysis} to do
 * the cleanup itself, closing a module cycle.
 */
@Getter
public class FileDeletedEvent extends ApplicationEvent {

  private final UUID fileId;

  public FileDeletedEvent(Object source, UUID fileId) {
    super(source);
    this.fileId = fileId;
  }
}
