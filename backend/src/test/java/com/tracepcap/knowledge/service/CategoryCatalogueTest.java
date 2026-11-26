package com.tracepcap.knowledge.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.knowledge.question.C2Question;
import com.tracepcap.knowledge.question.DataTransferQuestion;
import com.tracepcap.knowledge.question.DownloadsQuestion;
import com.tracepcap.knowledge.question.KerberosAttackQuestion;
import com.tracepcap.knowledge.question.LateralMovementQuestion;
import com.tracepcap.knowledge.question.MalwareQuestion;
import com.tracepcap.knowledge.question.RemoteAccessQuestion;
import com.tracepcap.knowledge.question.SignedInUserQuestion;
import com.tracepcap.knowledge.question.VictimQuestion;
import com.tracepcap.knowledge.spi.Category;
import com.tracepcap.knowledge.spi.StandardQuestion;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

/** The framework's categories and how today's questions map onto them (the docs' coverage table). */
class CategoryCatalogueTest {

  private static final List<StandardQuestion> QUESTIONS = List.of(
      new VictimQuestion(), new SignedInUserQuestion(), new MalwareQuestion(), new C2Question(),
      new DownloadsQuestion(), new DataTransferQuestion(), new RemoteAccessQuestion(),
      new LateralMovementQuestion(), new KerberosAttackQuestion());

  private final CategoryCatalogue catalogue = new CategoryCatalogue(QUESTIONS);

  private Map<Category, CategoryCatalogue.Entry> byCategory() {
    return catalogue.entries().stream()
        .collect(Collectors.toMap(CategoryCatalogue.Entry::category, e -> e));
  }

  @Test
  void listsEveryCategoryOnceInFrameworkOrder() {
    assertThat(catalogue.entries()).extracting(CategoryCatalogue.Entry::category)
        .containsExactly(Category.values());
    assertThat(catalogue.entries()).extracting(e -> e.category().axis())
        .isSortedAccordingTo(Enum::compareTo);
  }

  @Test
  void activitiesAreTheFourteenAttackTactics() {
    List<Category> activities = Arrays.stream(Category.values())
        .filter(c -> c.axis() == Category.Axis.ACTIVITY).toList();
    assertThat(activities).hasSize(14);
    assertThat(activities).allSatisfy(c -> assertThat(c.attackId()).matches("TA00\\d\\d"));
    assertThat(activities).extracting(Category::attackId).doesNotHaveDuplicates();
    assertThat(Arrays.stream(Category.values()).filter(c -> c.axis() != Category.Axis.ACTIVITY))
        .allSatisfy(c -> assertThat(c.attackId()).isNull());
  }

  @Test
  void keysAreUniqueKebabCase() {
    assertThat(Category.values()).extracting(Category::key)
        .doesNotHaveDuplicates()
        .allSatisfy(k -> assertThat(k).matches("[a-z][a-z0-9]*(-[a-z0-9]+)*"));
  }

  @Test
  void categoriesACaptureCantShowSayWhy() {
    assertThat(Category.values())
        .filteredOn(c -> c.visibility() == Category.Visibility.NEVER
            || c.visibility() == Category.Visibility.RARELY)
        .isNotEmpty()
        .allSatisfy(c -> assertThat(c.unseenReason()).isNotBlank());
  }

  @Test
  void mapsTodaysQuestionsAsTheCoverageTableDoes() {
    var m = byCategory();
    assertThat(m.get(Category.VICTIM).questions()).containsExactly("victim");
    assertThat(m.get(Category.SIGNED_IN_USER).questions()).containsExactly("signed-in-user");
    assertThat(m.get(Category.C2_SERVER).questions()).containsExactly("c2");
    assertThat(m.get(Category.REMOTE_ACCESS_SERVER).questions()).containsExactly("remote-access");
    assertThat(m.get(Category.COMMAND_AND_CONTROL).questions())
        .containsExactly("c2", "malware", "remote-access");
    assertThat(m.get(Category.INITIAL_ACCESS).questions()).containsExactly("downloads");
    assertThat(m.get(Category.EXECUTION).questions()).containsExactly("downloads");
    assertThat(m.get(Category.CREDENTIAL_ACCESS).questions()).containsExactly("kerberos-attack");
    assertThat(m.get(Category.LATERAL_MOVEMENT).questions()).containsExactly("lateral-movement");
    assertThat(m.get(Category.EXFILTRATION).questions()).containsExactly("data-transfer");
  }

  @Test
  void aCategoryNoQuestionCoversIsStillListed() {
    var m = byCategory();
    for (Category c : List.of(Category.RECONNAISSANCE, Category.DISCOVERY, Category.DEFENSE_EVASION,
        Category.COLLECTION, Category.IMPACT, Category.HONEYPOT, Category.SCANNER)) {
      assertThat(m.get(c).unchecked()).as(c.name()).isTrue();
      assertThat(m.get(c).evidence()).as(c.name()).isEmpty();
    }
  }

  @Test
  void evidenceSaysWhichQuestionReadsItAndWhatItShows() {
    var lateral = byCategory().get(Category.LATERAL_MOVEMENT).evidence();
    assertThat(lateral).extracting(e -> e.source().label()).containsExactly("SMB", "DCE-RPC");
    assertThat(lateral).allSatisfy(e -> {
      assertThat(e.question()).isEqualTo("lateral-movement");
      assertThat(e.source().shows()).isNotBlank();
    });
    // A check that reads alerts on any traffic declares none, so its categories never go
    // not-observable for want of a protocol.
    assertThat(byCategory().get(Category.C2_SERVER).evidence()).isEmpty();
    assertThat(byCategory().get(Category.C2_SERVER).readsAnyTraffic()).isTrue();
    assertThat(byCategory().get(Category.LATERAL_MOVEMENT).readsAnyTraffic()).isFalse();
  }

  @Test
  void downloadsReadAnyTraffic() {
    // Files are carved from any stream, not only HTTP: no protocol's absence rules them out.
    assertThat(byCategory().get(Category.INITIAL_ACCESS).readsAnyTraffic()).isTrue();
    assertThat(byCategory().get(Category.INITIAL_ACCESS).evidence()).isEmpty();
  }

  @Test
  void signedInUserReadsEveryProtocolItsSourcesRideOn() {
    // Kerberos AS-REQ, NTLM (inside SMB, HTTP, DCE-RPC) and the LDAP and SAMR name lookups.
    assertThat(byCategory().get(Category.SIGNED_IN_USER).evidence())
        .extracting(e -> e.source().label())
        .containsExactly("Kerberos", "LDAP", "NTLM", "SMB", "DCE-RPC", "HTTP");
  }

  @Test
  void aCategoryNoQuestionCoversReadsNothing() {
    assertThat(byCategory().get(Category.RECONNAISSANCE).readsAnyTraffic()).isFalse();
  }
}
