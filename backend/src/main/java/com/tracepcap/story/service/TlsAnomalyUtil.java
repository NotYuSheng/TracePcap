package com.tracepcap.story.service;

import com.tracepcap.analysis.spi.ConversationLookup.ConversationFacts;
import java.time.LocalDateTime;
import java.util.Set;

/** Shared TLS anomaly detection logic used by StoryService and StoryAggregatesService. */
public final class TlsAnomalyUtil {

  static final Set<String> KNOWN_CA_KEYWORDS =
      Set.of(
          "let's encrypt",
          "digicert",
          "comodo",
          "sectigo",
          "globalsign",
          "godaddy",
          "entrust",
          "amazon",
          "microsoft",
          "google",
          "apple",
          "verisign",
          "thawte",
          "isrg",
          "zerossl");

  private TlsAnomalyUtil() {}

  public static boolean isKnownCa(String issuer) {
    if (issuer == null) return false;
    String lower = issuer.toLowerCase();
    return KNOWN_CA_KEYWORDS.stream().anyMatch(lower::contains);
  }

  public static boolean isExpired(ConversationFacts conv) {
    return conv.tls().tlsNotAfter() != null && conv.tls().tlsNotAfter().isBefore(LocalDateTime.now());
  }

  /**
   * Self-signed. When the certificate itself was seen (#1235) this is verified: issuer equals
   * subject and it checks out with its own key. Otherwise the subject and issuer text are compared.
   */
  public static boolean isSelfSigned(ConversationFacts conv) {
    if (conv.tls().cert() != null) return conv.tls().cert().selfSigned();
    return conv.tls().tlsSubject() != null
        && conv.tls().tlsIssuer() != null
        && conv.tls().tlsSubject().equalsIgnoreCase(conv.tls().tlsIssuer());
  }

  public static boolean isUnknownCa(ConversationFacts conv) {
    return conv.tls().tlsIssuer() != null && !isKnownCa(conv.tls().tlsIssuer());
  }

  /** A key too short to trust (#1235): RSA/DSA under 2048 bits, EC under 256. */
  public static boolean isWeakKey(ConversationFacts conv) {
    return conv.tls().cert() != null && conv.tls().cert().weakKey();
  }

  /** Signed with MD5 or SHA-1 (#1235). */
  public static boolean isWeakSignature(ConversationFacts conv) {
    return conv.tls().cert() != null && conv.tls().cert().weakSignature();
  }

  /**
   * The certificate's names don't cover the server name the client asked for (#1235): a
   * misconfiguration, interception, or a server pretending to be something it isn't.
   */
  public static boolean isNameMismatch(ConversationFacts conv) {
    return conv.tls().cert() != null
        && Boolean.FALSE.equals(conv.tls().cert().covers(conv.tls().hostname()));
  }

  public static boolean isNoteworthy(ConversationFacts conv) {
    if (isExpired(conv)) return true;
    if (isWeakKey(conv) || isWeakSignature(conv) || isNameMismatch(conv)) return true;
    if (isSelfSigned(conv)) return true;
    if (isUnknownCa(conv)) return true;
    {
      for (String r : conv.findings().flowRisks()) {
        if (r.contains("tls") || r.contains("certificate") || r.contains("ssl")) return true;
      }
    }
    return false;
  }
}
