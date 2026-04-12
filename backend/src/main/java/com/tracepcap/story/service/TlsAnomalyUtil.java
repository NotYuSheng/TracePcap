package com.tracepcap.story.service;

import com.tracepcap.analysis.entity.ConversationEntity;
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

  public static boolean isExpired(ConversationEntity conv) {
    return conv.getTlsNotAfter() != null && conv.getTlsNotAfter().isBefore(LocalDateTime.now());
  }

  public static boolean isSelfSigned(ConversationEntity conv) {
    return conv.getTlsSubject() != null
        && conv.getTlsIssuer() != null
        && conv.getTlsSubject().equalsIgnoreCase(conv.getTlsIssuer());
  }

  public static boolean isUnknownCa(ConversationEntity conv) {
    return conv.getTlsIssuer() != null && !isKnownCa(conv.getTlsIssuer());
  }

  public static boolean isNoteworthy(ConversationEntity conv) {
    if (isExpired(conv)) return true;
    if (isSelfSigned(conv)) return true;
    if (isUnknownCa(conv)) return true;
    if (conv.getFlowRisks() != null) {
      for (String r : conv.getFlowRisks()) {
        if (r.contains("tls") || r.contains("certificate") || r.contains("ssl")) return true;
      }
    }
    return false;
  }
}
