package com.tracepcap.file.event;

import java.util.UUID;
import lombok.Getter;
import org.springframework.context.ApplicationEvent;

/**
 * A capture was re-analysed as a new version (#915 phase 3). Published inside the transaction that
 * creates the version, before its analysis starts, so a synchronous listener can copy what belongs
 * to the capture (its own detection rules) and the analysis sees it. Keeps {@code file} from
 * depending on those modules.
 */
@Getter
public class FileVersionCreatedEvent extends ApplicationEvent {

  private final UUID versionId;
  private final UUID fromId;

  public FileVersionCreatedEvent(Object source, UUID versionId, UUID fromId) {
    super(source);
    this.versionId = versionId;
    this.fromId = fromId;
  }
}
