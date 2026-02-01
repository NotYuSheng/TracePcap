package com.tracepcap.file.event;

import lombok.Getter;
import org.springframework.context.ApplicationEvent;

import java.util.UUID;

/**
 * Event published when a file is successfully uploaded
 */
@Getter
public class FileUploadedEvent extends ApplicationEvent {

    private final UUID fileId;

    public FileUploadedEvent(Object source, UUID fileId) {
        super(source);
        this.fileId = fileId;
    }
}
