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

  public static boolean isSelfSigned(ConversationFacts conv) {
    return conv.tls().tlsSubject() != null
        && conv.tls().tlsIssuer() != null
        && conv.tls().tlsSubject().equalsIgnoreCase(conv.tls().tlsIssuer());
  }

  public static boolean isUnknownCa(ConversationFacts conv) {
    return conv.tls().tlsIssuer() != null && !isKnownCa(conv.tls().tlsIssuer());
  }

  public static boolean isNoteworthy(ConversationFacts conv) {
    if (isExpired(conv)) return true;
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
