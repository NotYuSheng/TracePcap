package com.tracepcap.analysis.spi;

import java.util.List;
import java.util.UUID;

/**
 * Read port for per-file Windows-identity claims (#809): the seam downstream stages consume
 * without reaching into {@code analysis}' repositories or entities — same shape and reasoning as
 * {@link HostClassificationLookup}.
 */
public interface WindowsIdentityClaimLookup {

  /**
   * Canonical claim-source identifiers, kept here as shared vocabulary — same reasoning as {@link
   * ServiceLogRoles}: consumers (the adjudicator) depend on this contract rather than on the
   * concrete resolver in {@code analysis.service}, which they are not allowed to import.
   */
  String SOURCE_KERBEROS_AS_REQ = "kerberos_as_req";

  String SOURCE_LDAP_DN = "ldap_dn";

  /** One Windows-identity claim, as adjudication needs it — no persistence-shaped fields. */
  record UsernameClaim(String ip, String username, String source) {}

  /** Every Windows-identity claim recorded for a file. Never contains null elements. */
  List<UsernameClaim> claimsForFile(UUID fileId);
}
