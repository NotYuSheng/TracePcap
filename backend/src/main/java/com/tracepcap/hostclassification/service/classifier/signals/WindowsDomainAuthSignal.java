package com.tracepcap.hostclassification.service.classifier.signals;

import com.tracepcap.analysis.service.WindowsIdentityResolverService;
import com.tracepcap.analysis.service.WindowsIdentityResolverService.Claim;
import com.tracepcap.hostclassification.service.classifier.DeviceClassificationSignal;
import com.tracepcap.hostclassification.service.classifier.DeviceTypes;
import com.tracepcap.hostclassification.service.classifier.HostContext;
import com.tracepcap.hostclassification.service.classifier.ScoreBoard;
import java.util.LinkedHashSet;
import java.util.Set;
import org.springframework.stereotype.Component;

/**
 * Windows domain sign-in (#809): a host seen authenticating to Active Directory — a Kerberos AS-REQ
 * naming a principal, or an LDAP directory lookup of a person's account — is a domain-joined Windows
 * workstation, so this votes toward {@code LAPTOP_DESKTOP}. This is what surfaces the victim's real
 * identity that the #808 CTF demo found TracePcap was missing: the sign-in name rides along in the
 * reason string (and is recorded as the host's signed-in-user attribute by the classifier).
 *
 * <p>Two claim sources with different strength (see {@link WindowsIdentityResolverService}):
 *
 * <ul>
 *   <li><b>Kerberos AS-REQ</b> — MEASURED: the client itself authenticated as this principal. Strong
 *       laptop/desktop evidence, weighted comparably to a matching OUI vendor.
 *   <li><b>LDAP directory lookup</b> — REPORTED and weaker: the host queried an account's directory
 *       entry, which is a Windows-workstation behaviour but not proof of who is signed in. Lower
 *       weight, and only counted on its own when no Kerberos claim was seen.
 * </ul>
 *
 * <p>The resolver already excludes machine-account principals and never attributes a KDC's own IP,
 * so a claim present here always belongs to a real workstation sign-in.
 */
@Component
public class WindowsDomainAuthSignal implements DeviceClassificationSignal {

  static final int KERBEROS_WEIGHT = 40;
  static final int LDAP_WEIGHT = 15;

  @Override
  public String name() {
    return "windows-domain-auth";
  }

  @Override
  public void contribute(HostContext ctx, ScoreBoard board) {
    Set<String> kerberosNames = namesForSource(ctx, WindowsIdentityResolverService.SOURCE_KERBEROS_AS_REQ);
    Set<String> ldapNames = namesForSource(ctx, WindowsIdentityResolverService.SOURCE_LDAP_DN);

    if (!kerberosNames.isEmpty()) {
      board.add(
          DeviceTypes.LAPTOP_DESKTOP,
          KERBEROS_WEIGHT,
          "Windows domain sign-in as "
              + quoteJoin(kerberosNames)
              + " (Kerberos AS-REQ) → +"
              + KERBEROS_WEIGHT);
    }

    if (!ldapNames.isEmpty()) {
      board.add(
          DeviceTypes.LAPTOP_DESKTOP,
          LDAP_WEIGHT,
          "Directory lookup of "
              + quoteJoin(ldapNames)
              + " (LDAP) → +"
              + LDAP_WEIGHT);
    }
  }

  private Set<String> namesForSource(HostContext ctx, String source) {
    Set<String> names = new LinkedHashSet<>();
    for (Claim c : ctx.windowsIdentityClaims()) {
      if (source.equals(c.source())) names.add(c.username());
    }
    return names;
  }

  private String quoteJoin(Set<String> names) {
    StringBuilder sb = new StringBuilder();
    for (String n : names) {
      if (sb.length() > 0) sb.append(", ");
      sb.append('"').append(n).append('"');
    }
    return sb.toString();
  }
}
