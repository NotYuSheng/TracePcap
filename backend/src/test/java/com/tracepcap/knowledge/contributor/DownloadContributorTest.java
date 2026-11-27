package com.tracepcap.knowledge.contributor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.tracepcap.analysis.spi.ConversationLookup;
import com.tracepcap.analysis.spi.ConversationLookup.ConversationFacts;
import com.tracepcap.analysis.spi.ConversationLookup.Findings;
import com.tracepcap.analysis.spi.ConversationLookup.FlowIdentity;
import com.tracepcap.analysis.spi.ConversationLookup.TlsFacts;
import com.tracepcap.extraction.spi.ExtractedFileLookup;
import com.tracepcap.extraction.spi.ExtractedFileLookup.ExtractedFileFacts;
import com.tracepcap.knowledge.question.DownloadsQuestion;
import com.tracepcap.knowledge.spi.Answer;
import com.tracepcap.knowledge.spi.CaseKnowledgeBuilder;
import com.tracepcap.knowledge.spi.Grade;
import com.tracepcap.knowledge.spi.KnowledgeContext;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;

/** Files and hosts from the 2024-08-15 WarmCookie training capture. */
class DownloadContributorTest {

  private static final UUID FILE = UUID.randomUUID();

  private static ConversationFacts conv(UUID id, String host, String external, String serverName) {
    return new ConversationFacts(
        id, FILE,
        new FlowIdentity(host, 49810, external, 80, host, 49810, "TCP", 120, 160_000,
            LocalDateTime.of(2024, 8, 15, 8, 12, 3), null),
        new TlsFacts(serverName, null, null, null, null, null, null, null, null),
        new Findings(null, null, null, List.of(), List.of(), List.of(), List.of()));
  }

  @SuppressWarnings("unchecked")
  private static List<Answer> run(List<ConversationFacts> convs, List<ExtractedFileFacts> files) {
    ConversationLookup conversations = mock(ConversationLookup.class);
    when(conversations.conversationFacts(FILE)).thenReturn(convs);
    ExtractedFileLookup lookup = mock(ExtractedFileLookup.class);
    when(lookup.extractedFiles(FILE)).thenReturn(files);
    ObjectProvider<ExtractedFileLookup> provider = mock(ObjectProvider.class);
    when(provider.getIfAvailable()).thenReturn(lookup);
    CaseKnowledgeBuilder board = new CaseKnowledgeBuilder(FILE);
    new DownloadContributor(provider).contribute(KnowledgeContext.of(FILE, conversations, null, com.tracepcap.common.net.LocalityRules.RFC_ONLY), board);
    return new DownloadsQuestion().answer(board.build());
  }

  @Test
  void aProgramFetchedFromOutside_isListedWithItsHash() {
    UUID c = UUID.randomUUID();
    List<Answer> a =
        run(
            List.of(conv(c, "10.8.15.133", "72.5.43.29", null)),
            List.of(new ExtractedFileFacts(c, "0f60a3e7baecf2748b1c8183ed37d1e4",
                "application/x-msdownload; format=pe64", 159_232L,
                "B7AEC5F73D2A6BBD8CD920EDB4760E2EDADC98C3A45BF4FA994D47CA9CBD02F6", "tshark_http", false)));
    assertThat(a).singleElement().satisfies(x -> {
      assertThat(x.grade()).isEqualTo(Grade.MEASURED);
      assertThat(x.attributes()).containsEntry("sha256",
          "b7aec5f73d2a6bbd8cd920edb4760e2edadc98c3a45bf4fa994d47ca9cbd02f6");
      assertThat(x.headline()).contains("10.8.15.133 downloaded").contains("Windows program or DLL")
          .contains("155.5 KB").contains("72.5.43.29");
    });
  }

  @Test
  void carvedGuesses_updateServers_harmlessTypes_andInternalCopies_areNotDownloads() {
    UUID carved = UUID.randomUUID(), update = UUID.randomUUID(), image = UUID.randomUUID(), lan = UUID.randomUUID();
    assertThat(
            run(
                List.of(
                    conv(carved, "10.8.15.133", "72.5.43.29", null),
                    conv(update, "10.8.15.133", "199.232.214.172", "au.download.windowsupdate.com"),
                    conv(image, "10.8.15.133", "23.220.103.8", null),
                    conv(lan, "10.8.15.133", "10.8.15.4", null)),
                List.of(
                    new ExtractedFileFacts(carved, "stream-5c5b8ce2-10587.dll", "application/x-msdownload", 295_258L, "1645fc", "magic_bytes", false),
                    new ExtractedFileFacts(update, "am_delta_patch.exe", "application/x-msdownload", 398_944L, "3e3466", "tshark_http", false),
                    new ExtractedFileFacts(image, "logo.png", "image/png", 9_000L, "aa", "tshark_http", false),
                    new ExtractedFileFacts(lan, "tool.exe", "application/x-msdownload", 9_000L, "bb", "tshark_http", false))))
        .isEmpty();
  }

  @Test
  void theSameFileTwice_isOneAnswer() {
    UUID c1 = UUID.randomUUID(), c2 = UUID.randomUUID();
    assertThat(
            run(
                List.of(conv(c1, "10.8.15.133", "104.21.55.70", "quote.checkfedexexp.com"),
                    conv(c2, "10.8.15.133", "104.21.55.70", "quote.checkfedexexp.com")),
                List.of(
                    new ExtractedFileFacts(c1, "Invoice.zip", "application/zip", 2_767_804L, "798563fc", "tshark_http", false),
                    new ExtractedFileFacts(c2, "Invoice(1).zip", "application/zip", 2_767_804L, "798563fc", "tshark_http", false))))
        .singleElement()
        .satisfies(x -> assertThat(x.headline()).contains("from quote.checkfedexexp.com").contains("archive"));
  }

  @Test
  void anUpdateFetchedOverPlainHttp_isRecognisedByItsUrl() {
    // 2025-01-22: a Defender update over HTTP had no TLS name to go by.
    UUID c = UUID.randomUUID();
    assertThat(
            run(
                List.of(conv(c, "10.1.17.215", "199.232.214.172", null)),
                List.of(new ExtractedFileFacts(c, "am_delta_patch_1.421.1491.0.exe", "application/x-msdownload", 398_944L,
                    "3e3466", "tshark_http", false,
                    "http://au.download.windowsupdate.com/c/msdownload/update/am_delta_patch_1.421.1491.0.exe"))))
        .isEmpty();
  }

  @Test
  void theAnswerSaysTheUrl() {
    UUID c = UUID.randomUUID();
    assertThat(
            run(
                List.of(conv(c, "10.8.15.133", "72.5.43.29", null)),
                List.of(new ExtractedFileFacts(c, "0f60a3e7baecf2748b1c8183ed37d1e4", "application/x-msdownload", 159_232L,
                    "b7aec5f7", "tshark_http", false, "http://72.5.43.29/data/0f60a3e7baecf2748b1c8183ed37d1e4"))))
        .singleElement()
        .satisfies(x -> assertThat(x.headline()).contains("from http://72.5.43.29/data/0f60a3e7baecf2748b1c8183ed37d1e4 (72.5.43.29)"));
  }

  @Test
  void aPowerShellScriptTypedAsText_isADownload_byItsName() {
    // 2025-01-22: the C2 served pas.ps1; content detection says text/plain.
    UUID c = UUID.randomUUID();
    assertThat(
            run(
                List.of(conv(c, "10.1.17.215", "5.252.153.241", null)),
                List.of(new ExtractedFileFacts(c, "pas.ps1", "text/plain", 1_520L, "a833f27c", "tshark_http", false,
                    "http://5.252.153.241/api/file/get-file/pas.ps1"))))
        .singleElement()
        .satisfies(x -> assertThat(x.headline()).contains("pas.ps1 (PowerShell script"));
  }

  @Test
  void gzipIsNotAnArchiveDownload() {
    // Holdout 2026-09-11 (Kongtuke): 55 gzip-compressed C2 responses counted as archives.
    UUID c = UUID.randomUUID();
    assertThat(
            run(
                List.of(conv(c, "10.9.11.135", "86.106.87.134", null)),
                List.of(new ExtractedFileFacts(c, "ho", "application/gzip", 27_000L, "aa", "tshark_http", false,
                    "http://know.mom-nower.com/0l6yonrds/we/ho"))))
        .isEmpty();
  }

  @Test
  void oneServerCannotFloodTheAnswers_threeLargestThenACount() {
    List<ConversationFacts> convs = new java.util.ArrayList<>();
    List<ExtractedFileFacts> files = new java.util.ArrayList<>();
    for (int i = 0; i < 7; i++) {
      UUID c = UUID.randomUUID();
      convs.add(conv(c, "10.9.11.135", "86.106.87.134", null));
      files.add(new ExtractedFileFacts(c, "f" + i + ".zip", "application/zip", 1_000L * (i + 1), "sha" + i,
          "tshark_http", false));
    }
    List<Answer> a = run(convs, files);
    assertThat(a).hasSize(4);
    assertThat(a.get(0).headline()).contains("f6.zip");
    assertThat(a.get(3).headline()).contains("4 more files from 86.106.87.134");
  }
}
