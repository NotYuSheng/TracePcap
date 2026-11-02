package com.tracepcap.filter.service;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracepcap.common.exception.LlmException;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.service.FileService;
import com.tracepcap.file.service.StorageService;
import com.tracepcap.story.service.LlmClient;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/** Giving up on the model must reach the user as an LLM failure, not an unexpected error. */
class FilterServiceGenerationTest {

  @Test
  void runningOutOfAttemptsIsAnLlmFailureThatKeepsTheReason() {
    UUID fileId = UUID.randomUUID();
    FileEntity file = mock(FileEntity.class);
    when(file.getMinioPath()).thenReturn("files/capture.pcap");
    FileService fileService = mock(FileService.class);
    when(fileService.getFileById(fileId)).thenReturn(file);
    LlmClient llmClient = mock(LlmClient.class);
    when(llmClient.generateCompletion(anyString(), anyString())).thenReturn("not json");

    FilterService service =
        new FilterService(llmClient, fileService, mock(StorageService.class), new ObjectMapper());

    assertThatThrownBy(() -> service.generateFilter(fileId, "dns traffic"))
        .isInstanceOf(LlmException.class)
        .hasFieldOrPropertyWithValue("errorCode", LlmException.ErrorCode.LLM_BAD_RESPONSE)
        .hasMessageContaining("after 3 attempts")
        .hasMessageContaining("invalid JSON");
    verify(llmClient, times(3)).generateCompletion(anyString(), any());
  }
}
