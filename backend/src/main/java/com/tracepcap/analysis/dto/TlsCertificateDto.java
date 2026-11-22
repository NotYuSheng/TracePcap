package com.tracepcap.analysis.dto;

import com.tracepcap.analysis.spi.ConversationLookup.CertFacts;
import java.util.List;

/**
 * The server certificate's detail (#1235), with the checks worked out here so every client reads
 * the same verdicts. Absent from a conversation when the certificate wasn't seen.
 *
 * @param coversServerName whether the SANs cover the conversation's server name (SNI); null when
 *     there's no name to check or no SANs
 */
public record TlsCertificateDto(
    List<String> sans,
    String keyType,
    Integer keyBits,
    String signatureAlgorithm,
    boolean selfSigned,
    int chainLength,
    boolean weakKey,
    boolean weakSignature,
    Boolean coversServerName) {

  public static TlsCertificateDto from(CertFacts c, String serverName) {
    if (c == null) return null;
    return new TlsCertificateDto(
        c.sans(), c.keyType(), c.keyBits(), c.signatureAlgorithm(), c.selfSigned(),
        c.chainLength(), c.weakKey(), c.weakSignature(), c.covers(serverName));
  }
}
