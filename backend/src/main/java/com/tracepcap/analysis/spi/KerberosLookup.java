package com.tracepcap.analysis.spi;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

/**
 * The tickets and errors a domain controller returned (#1267), from Suricata's krb5 records, for the
 * knowledge layer's Kerberos findings.
 */
public interface KerberosLookup {

  /**
   * One kind of reply on a conversation, grouped.
   *
   * @param msgType KRB_AS_REP, KRB_TGS_REP or KRB_ERROR
   * @param account the account the request was for (an error takes it from its request)
   * @param service the service ticket asked for ("krbtgt/CORP.LOCAL", "MSSQLSvc/db:1433")
   * @param errorCode e.g. KDC_ERR_PREAUTH_FAILED; null for a ticket
   * @param encryption the ticket's encryption type; null for an error
   * @param weak Suricata's own judgement of that encryption (RC4, DES)
   */
  record KerberosFacts(
      UUID conversationId, LocalDateTime firstTime, String client, String kdc, String msgType,
      String account, String service, String realm, String errorCode, String encryption,
      boolean weak, int count) {}

  /** A capture's replies, oldest first. */
  List<KerberosFacts> forFile(UUID fileId);
}
