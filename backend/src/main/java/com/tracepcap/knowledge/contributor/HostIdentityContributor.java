package com.tracepcap.knowledge.contributor;

import com.tracepcap.analysis.service.WindowsIdentityResolverService;
import com.tracepcap.analysis.spi.HostClassificationLookup;
import com.tracepcap.analysis.spi.HostClassificationLookup.HostFacts;
import com.tracepcap.knowledge.spi.CaseKnowledgeBuilder;
import com.tracepcap.knowledge.spi.EntityRef;
import com.tracepcap.knowledge.spi.Grade;
import com.tracepcap.knowledge.spi.KnowledgeContributor;
import com.tracepcap.knowledge.spi.Relationship;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * Posts each classified host as a board entity, and — where a Windows sign-in was recovered
 * (#809) — the user as an entity plus a {@code signed-in-as} relationship. This is one of the two
 * facts the STRRAT demo showed Story mode was missing: with this on the board, "who is the victim?"
 * becomes a query, not a guess.
 */
@Component
@RequiredArgsConstructor
public class HostIdentityContributor implements KnowledgeContributor {

  static final String SIGNED_IN_AS = "signed-in-as";

  private final HostClassificationLookup hostClassificationLookup;

  @Override
  public String name() {
    return "host-identity";
  }

  @Override
  public void contribute(UUID fileId, CaseKnowledgeBuilder board) {
    for (HostFacts host : hostClassificationLookup.hostFacts(fileId)) {
      EntityRef hostRef = EntityRef.host(host.ip());
      board.addEntity(hostRef, hostAttributes(host));

      String user = host.loggedInUser();
      if (user != null && !user.isBlank()) {
        String source = host.loggedInUserSource();
        board.addEntity(EntityRef.user(user), Map.of("source", nullToUnknown(source)));
        board.addRelationship(
            Relationship.of(hostRef, SIGNED_IN_AS, EntityRef.user(user), gradeForSource(source), name()));
      }
    }
  }

  private Map<String, Object> hostAttributes(HostFacts host) {
    Map<String, Object> attrs = new LinkedHashMap<>();
    put(attrs, "deviceType", host.deviceType());
    attrs.put("confidence", host.confidence());
    put(attrs, "mac", host.mac());
    put(attrs, "manufacturer", host.manufacturer());
    put(attrs, "hostname", host.hostname());
    put(attrs, "hostnameSource", host.hostnameSource());
    if (host.ttl() != null) attrs.put("ttl", host.ttl());
    if (host.serviceRoles() != null && !host.serviceRoles().isEmpty()) {
      attrs.put("serviceRoles", host.serviceRoles());
    }
    return attrs;
  }

  /**
   * A Kerberos AS-REQ is MEASURED (the client authenticated as this principal); an LDAP directory
   * lookup is REPORTED (a party named an account). Anything else is treated as inferred.
   */
  private Grade gradeForSource(String source) {
    if (WindowsIdentityResolverService.SOURCE_KERBEROS_AS_REQ.equals(source)) return Grade.MEASURED;
    if (WindowsIdentityResolverService.SOURCE_LDAP_DN.equals(source)) return Grade.REPORTED;
    return Grade.INFERRED;
  }

  private static void put(Map<String, Object> attrs, String key, String value) {
    if (value != null && !value.isBlank()) attrs.put(key, value);
  }

  private static String nullToUnknown(String s) {
    return (s == null || s.isBlank()) ? "unknown" : s;
  }
}
