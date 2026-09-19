package com.tracepcap.knowledge.contributor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import com.tracepcap.analysis.spi.HostClassificationLookup;
import com.tracepcap.analysis.spi.HostClassificationLookup.HostFacts;
import com.tracepcap.knowledge.spi.CaseKnowledge;
import com.tracepcap.knowledge.spi.CaseKnowledgeBuilder;
import com.tracepcap.knowledge.spi.EntityRef;
import com.tracepcap.knowledge.spi.EntityType;
import com.tracepcap.knowledge.spi.Grade;
import com.tracepcap.knowledge.spi.Relationship;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class HostIdentityContributorTest {

  private static final UUID FILE = UUID.randomUUID();

  @Mock private HostClassificationLookup hostClassificationLookup;

  private CaseKnowledge run(HostFacts... hosts) {
    when(hostClassificationLookup.hostFacts(FILE)).thenReturn(List.of(hosts));
    CaseKnowledgeBuilder board = new CaseKnowledgeBuilder(FILE);
    new HostIdentityContributor(hostClassificationLookup).contribute(FILE, board);
    return board.build();
  }

  @Test
  void kerberosSignIn_postsHostAndUserEntitiesAndAMeasuredSignedInAsEdge() {
    HostFacts victim =
        new HostFacts(
            "172.16.1.66", "00:1e:64:ec:f3:08", "Intel Corporate", "DESKTOP-SKBR25F", "mdns",
            "ccollier", "kerberos_as_req", 128, "LAPTOP_DESKTOP", 100, List.of());

    CaseKnowledge k = run(victim);

    assertThat(k.entitiesOfType(EntityType.HOST)).singleElement()
        .satisfies(h -> assertThat(h.key()).isEqualTo("172.16.1.66"));
    assertThat(k.entitiesOfType(EntityType.USER)).singleElement()
        .satisfies(u -> assertThat(u.key()).isEqualTo("ccollier"));

    List<Relationship> signedIn = k.relationshipsWithPredicate("signed-in-as");
    assertThat(signedIn).singleElement().satisfies(r -> {
      assertThat(r.from()).isEqualTo(EntityRef.host("172.16.1.66"));
      assertThat(r.to()).isEqualTo(EntityRef.user("ccollier"));
      assertThat(r.grade()).isEqualTo(Grade.MEASURED); // Kerberos AS-REQ is measured
    });
  }

  @Test
  void ldapOnlySignIn_isGradedReported() {
    HostFacts host =
        new HostFacts(
            "10.0.0.5", null, null, null, null, "Clark Collier", "ldap_dn", null,
            "LAPTOP_DESKTOP", 80, List.of());

    CaseKnowledge k = run(host);

    assertThat(k.relationshipsWithPredicate("signed-in-as")).singleElement()
        .satisfies(r -> assertThat(r.grade()).isEqualTo(Grade.REPORTED));
  }

  @Test
  void hostWithNoSignIn_postsOnlyTheHost() {
    HostFacts host =
        new HostFacts("10.0.0.9", null, null, null, null, null, null, 64, "SERVER", 90, List.of("dns"));

    CaseKnowledge k = run(host);

    assertThat(k.entitiesOfType(EntityType.HOST)).hasSize(1);
    assertThat(k.entitiesOfType(EntityType.USER)).isEmpty();
    assertThat(k.relationshipsWithPredicate("signed-in-as")).isEmpty();
  }
}
