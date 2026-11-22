package com.tracepcap.extraction.service;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/** tshark --export-objects http names, verbatim from five training captures. */
class HttpObjectNamingTest {

  @Test
  void theQueryStringIsKept_andIllegalCharactersArePercentEncoded() {
    // 2024-08-15 WarmCookie: the ZIP that lost its conversation.
    assertThat(FileExtractionService.uriToBasename(
            "/managements?16553a25e45250a41fd5&endeds=MIGpq&Ld=9d7502d88d752a27b1d00587309184b5a215"))
        .isEqualTo("managements%3f16553a25e45250a41fd5&endeds=MIGpq&Ld=9d7502d88d752a27b1d00587309184b5a215");
    assertThat(FileExtractionService.uriToBasename("/fwlink/?LinkID=252669&clcid=0x409"))
        .isEqualTo("%3fLinkID=252669&clcid=0x409");
    assertThat(FileExtractionService.uriToBasename("/lookup?op=get&options=mr&search=0xF7B29119B5D7F848"))
        .isEqualTo("lookup%3fop=get&options=mr&search=0xF7B29119B5D7F848");
  }

  @Test
  void rootAndProxyStyleUris() {
    assertThat(FileExtractionService.uriToBasename("/")).isEqualTo("%2f");
    assertThat(FileExtractionService.uriToBasename("http://ip.webernetz.net/")).isEqualTo("ip.webernetz.net");
    assertThat(FileExtractionService.uriToBasename("/data/0f60a3e7baecf2748b1c8183ed37d1e4"))
        .isEqualTo("0f60a3e7baecf2748b1c8183ed37d1e4");
  }
}
