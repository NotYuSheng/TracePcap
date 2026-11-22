package com.tracepcap.analysis.service;

import com.tracepcap.analysis.spi.ConversationLookup.CertFacts;
import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import lombok.extern.slf4j.Slf4j;

/**
 * Reads what matters for judging a TLS server certificate (#1235) out of the DER Suricata logs
 * (eve {@code tls.certificate}, base64). Offline: {@code java.security.cert} only, no trust store
 * and no revocation lookups. That makes this a description of the certificate, never a verdict on
 * whether a browser would trust it.
 */
@Slf4j
public final class TlsCertificateParser {

  /** At most this many alternative names are kept; CDN certificates can list hundreds. */
  static final int MAX_SANS = 50;

  private TlsCertificateParser() {}

  /**
   * Parses Suricata's base64 DER leaf certificate, or returns null when it's absent or unreadable.
   * {@code chainLength} is how many certificates the server sent ({@code tls.chain}), leaf included.
   */
  public static CertFacts parse(String base64Der, int chainLength) {
    if (base64Der == null || base64Der.isBlank()) return null;
    try {
      byte[] der = Base64.getMimeDecoder().decode(base64Der);
      X509Certificate cert =
          (X509Certificate)
              CertificateFactory.getInstance("X.509")
                  .generateCertificate(new ByteArrayInputStream(der));
      PublicKey key = cert.getPublicKey();
      return new CertFacts(
          sans(cert),
          keyType(key),
          keyBits(key),
          cert.getSigAlgName(),
          isSelfSigned(cert),
          Math.max(1, chainLength));
    } catch (Exception e) {
      log.debug("Unreadable TLS certificate: {}", e.getMessage());
      return null;
    }
  }

  private static List<String> sans(X509Certificate cert) throws Exception {
    Collection<List<?>> names = cert.getSubjectAlternativeNames();
    List<String> out = new ArrayList<>();
    if (names == null) return out;
    for (List<?> n : names) {
      // 2 = dNSName, 7 = iPAddress (RFC 5280); both come back as strings from the JDK.
      Object type = n.get(0);
      if ((Integer.valueOf(2).equals(type) || Integer.valueOf(7).equals(type))
          && n.get(1) instanceof String s
          && !s.isBlank()) {
        out.add(s.trim());
        if (out.size() >= MAX_SANS) break;
      }
    }
    return out;
  }

  private static String keyType(PublicKey key) {
    if (key instanceof RSAPublicKey) return "RSA";
    if (key instanceof ECPublicKey) return "EC";
    if (key instanceof DSAPublicKey) return "DSA";
    return key.getAlgorithm();
  }

  private static Integer keyBits(PublicKey key) {
    if (key instanceof RSAPublicKey rsa) return rsa.getModulus().bitLength();
    if (key instanceof ECPublicKey ec) return ec.getParams().getCurve().getField().getFieldSize();
    if (key instanceof DSAPublicKey dsa) return dsa.getParams().getP().bitLength();
    return null;
  }

  /** Issuer equals subject and the signature checks out with the certificate's own key. */
  private static boolean isSelfSigned(X509Certificate cert) {
    if (!cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) return false;
    try {
      cert.verify(cert.getPublicKey());
      return true;
    } catch (Exception e) {
      return false;
    }
  }
}
