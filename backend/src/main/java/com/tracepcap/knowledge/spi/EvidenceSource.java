package com.tracepcap.knowledge.spi;

import java.util.List;

/**
 * A kind of traffic a check reads (the investigation framework): when none of a category's sources
 * is in a capture, that capture can't answer it, and the category is <em>not observable</em> rather
 * than open.
 *
 * @param label shown to people ("SMB", "Kerberos")
 * @param l7 tshark's dissected protocol names that mean it, upper case, as the Conversations filter
 *     takes them
 * @param apps nDPI's application names that mean it
 * @param shows what it shows for the check that reads it, in a line
 * @param byL7 link by tshark's name even when nDPI's is present: nDPI names TLS and HTTP sessions by
 *     service (Microsoft, GitHub), so for those tshark's name catches them all
 */
public record EvidenceSource(
    String label, List<String> l7, List<String> apps, String shows, boolean byL7) {

  public EvidenceSource {
    l7 = l7 == null ? List.of() : List.copyOf(l7);
    apps = apps == null ? List.of() : List.copyOf(apps);
  }

  /** The same traffic, saying what it shows for another check. */
  public EvidenceSource showing(String what) {
    return new EvidenceSource(label, l7, apps, what, byL7);
  }

  // Traffic the checks read, each defined once.
  public static final EvidenceSource KERBEROS =
      of("Kerberos", List.of("KERBEROS", "KRB5", "SPNEGO-KRB5"), List.of("Kerberos"));
  public static final EvidenceSource LDAP =
      of("LDAP", List.of("LDAP", "CLDAP"), List.of("LDAP", "CLDAP"));
  public static final EvidenceSource NTLM = of("NTLM", List.of("NTLMSSP"), List.of());
  public static final EvidenceSource SMB =
      of("SMB", List.of("SMB", "SMB2"), List.of("SMBv1", "SMBv23"));
  public static final EvidenceSource DCERPC = of("DCE-RPC", List.of("DCERPC"), List.of("DCERPC"));
  public static final EvidenceSource HTTP =
      new EvidenceSource("HTTP", List.of("HTTP"), List.of("HTTP"), null, true);

  private static EvidenceSource of(String label, List<String> l7, List<String> apps) {
    return new EvidenceSource(label, l7, apps, null, false);
  }
}
