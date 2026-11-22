package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.analysis.spi.ConversationLookup.CertFacts;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Certificates in src/test/resources/tls-certs: two generated with openssl for #1235 (a weak
 * self-signed RSA-1024/SHA-1 one, and an EC P-256 leaf signed by a separate CA), and one public
 * leaf exactly as Suricata logged it from the 2024-07-30 training capture.
 */
class TlsCertificateParserTest {

  private static String b64(String name) throws Exception {
    try (var in = TlsCertificateParserTest.class.getResourceAsStream("/tls-certs/" + name)) {
      return new String(in.readAllBytes(), StandardCharsets.US_ASCII).trim();
    }
  }

  @Test
  void realPublicCertificate_asSuricataLoggedIt() throws Exception {
    CertFacts c = TlsCertificateParser.parse(b64("microsoft-events.b64"), 2);
    assertThat(c).isNotNull();
    assertThat(c.sans()).contains("*.events.data.microsoft.com", "events.data.microsoft.com");
    assertThat(c.keyType()).isEqualTo("RSA");
    assertThat(c.keyBits()).isEqualTo(2048);
    assertThat(c.signatureAlgorithm()).isEqualTo("SHA256withRSA");
    assertThat(c.selfSigned()).isFalse();
    assertThat(c.chainLength()).isEqualTo(2);
    assertThat(c.weakKey()).isFalse();
    assertThat(c.weakSignature()).isFalse();
    assertThat(c.covers("v10.events.data.microsoft.com")).isTrue();
    assertThat(c.covers("events.data.microsoft.com")).isTrue();
    // A wildcard covers one label only.
    assertThat(c.covers("a.v10.events.data.microsoft.com")).isFalse();
    assertThat(c.covers("evil.example.com")).isFalse();
  }

  @Test
  void weakSelfSignedCertificate_isFlaggedOnEveryCount() throws Exception {
    CertFacts c = TlsCertificateParser.parse(b64("weak.b64"), 1);
    assertThat(c.selfSigned()).isTrue();
    assertThat(c.keyBits()).isEqualTo(1024);
    assertThat(c.weakKey()).isTrue();
    assertThat(c.signatureAlgorithm()).isEqualTo("SHA1withRSA");
    assertThat(c.weakSignature()).isTrue();
    assertThat(c.covers("WWW.weak.test.")).isTrue(); // case and a trailing dot don't matter
  }

  @Test
  void ecLeafSignedByACa_isSound_andIpSansAreKept() throws Exception {
    CertFacts c = TlsCertificateParser.parse(b64("leaf.b64"), 2);
    assertThat(c.keyType()).isEqualTo("EC");
    assertThat(c.keyBits()).isEqualTo(256);
    assertThat(c.weakKey()).isFalse();
    assertThat(c.signatureAlgorithm()).isEqualTo("SHA256withECDSA");
    assertThat(c.selfSigned()).isFalse();
    assertThat(c.sans()).containsExactly("www.sound.test", "192.0.2.10");
  }

  @Test
  void nothingToJudge_isUnknownNotAMismatch() throws Exception {
    CertFacts c = TlsCertificateParser.parse(b64("leaf.b64"), 1);
    assertThat(c.covers(null)).isNull();
    assertThat(new CertFacts(List.of(), "RSA", 2048, "SHA256withRSA", false, 1).covers("x.test")).isNull();
  }

  @Test
  void absentOrGarbage_isNull() {
    assertThat(TlsCertificateParser.parse(null, 1)).isNull();
    assertThat(TlsCertificateParser.parse("", 1)).isNull();
    assertThat(TlsCertificateParser.parse("bm90IGEgY2VydA==", 1)).isNull();
  }
}
