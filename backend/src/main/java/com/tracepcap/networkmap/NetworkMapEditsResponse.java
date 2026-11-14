package com.tracepcap.networkmap;

import java.time.LocalDateTime;

/** A capture's network map edits, with who last changed them and when (null when never edited). */
public record NetworkMapEditsResponse(NetworkMapEdits edits, LocalDateTime updatedAt, String updatedBy) {}
