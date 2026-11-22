package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;

/** #600: an operator-supplied Suricata ruleset, how it's dated, and that a broken one is never used. */
class SuricataRulesetTest {

  @TempDir Path tmp;

  private static final String RULE_A =
      "alert http $HOME_NET any -> $EXTERNAL_NET any (msg:\"ET MALWARE A\"; sid:1; rev:1;"
          + " metadata:created_at 2020_01_01, updated_at 2026_11_20;)";
  private static final String RULE_B =
      "alert dns any any -> any any (msg:\"ET INFO B\"; sid:2; rev:1; metadata:updated_at 2025_03_04;)";
  private static final String COMMENTED = "#alert tcp any any -> any any (msg:\"off\"; sid:3; rev:1; metadata:updated_at 2027_01_01;)";

  @Test
  void anEmptyOrMissingFolder_hasNoBundle_andAddingOneChangesTheFingerprint() throws Exception {
    assertThat(SuricataRuleset.fingerprint(tmp.resolve("missing"))).isEmpty();
    assertThat(SuricataRuleset.fingerprint(tmp)).isEmpty();
    Files.writeString(tmp.resolve("notes.txt"), "not a bundle");
    assertThat(SuricataRuleset.fingerprint(tmp)).isEmpty();
    Files.writeString(tmp.resolve("local.rules"), RULE_A);
    assertThat(SuricataRuleset.fingerprint(tmp)).contains("local.rules");
  }

  @Test
  void rulesFiles_areJoined_countedWithoutCommentedRules_andDatedByTheNewestUpdatedAt() throws Exception {
    Path in = Files.createDirectories(tmp.resolve("in"));
    Files.writeString(in.resolve("a.rules"), RULE_A + "\n" + COMMENTED + "\n");
    Files.writeString(in.resolve("b.rules"), RULE_B + "\n");
    Files.writeString(in.resolve("classification.config"), "config classification: trojan-activity,x,1\n");
    Path out = Files.createDirectories(tmp.resolve("out"));

    LocalDate date = SuricataRuleset.assemble(in, out);

    assertThat(date).isEqualTo(LocalDate.of(2026, 11, 20)); // the commented 2027 rule doesn't count
    assertThat(SuricataRuleset.countRules(out.resolve("suricata.rules"))).isEqualTo(2);
    assertThat(out.resolve("classification.config")).exists();
  }

  @Test
  void anEtTarball_isUnpacked_andDatedByItsNewestEntry() throws Exception {
    Path src = Files.createDirectories(tmp.resolve("src/rules"));
    Files.writeString(src.resolve("emerging-malware.rules"), RULE_A + "\n");
    Files.writeString(src.resolve("emerging-dns.rules"), RULE_B + "\n");
    Files.writeString(src.resolve("reference.config"), "config reference: url http://\n");
    Instant published = Instant.parse("2026-11-21T05:44:00Z");
    for (Path p : List.of(src.resolve("emerging-malware.rules"), src.resolve("emerging-dns.rules"), src.resolve("reference.config"))) {
      Files.setLastModifiedTime(p, FileTime.from(published));
    }
    Path in = Files.createDirectories(tmp.resolve("in"));
    Process tar =
        new ProcessBuilder("tar", "-czf", in.resolve("emerging.rules.tar.gz").toString(), "-C", tmp.resolve("src").toString(), "rules")
            .start();
    assertThat(tar.waitFor()).isZero();
    Path out = Files.createDirectories(tmp.resolve("out"));

    LocalDate date = SuricataRuleset.assemble(in, out);

    assertThat(date).isEqualTo(LocalDate.of(2026, 11, 21));
    assertThat(SuricataRuleset.countRules(out.resolve("suricata.rules"))).isEqualTo(2);
    assertThat(out.resolve("reference.config")).exists();
    assertThat(out.resolve("unpacked")).doesNotExist();
  }

  @Test
  void aBrokenBundle_isReported_andTheBuiltInRulesStay() throws Exception {
    Path in = Files.createDirectories(tmp.resolve("import"));
    Files.writeString(in.resolve("broken.rules"), "alert tcp any any -> any any (msg:\"broken\"; garbage;)\n");
    SuricataRuleset ruleset = ruleset(in);

    ruleset.checkImports();

    // Suricata either isn't installed here or refuses the rule: either way it isn't used.
    assertThat(ruleset.active().source()).isEqualTo("built-in");
    assertThat(ruleset.suricataArgs()).isEmpty();
    assertThat(ruleset.status().importError()).isNotBlank();
  }

  @Test
  void aBundleWithNoRules_isReported() throws Exception {
    Path in = Files.createDirectories(tmp.resolve("import"));
    Files.writeString(in.resolve("empty.rules"), COMMENTED + "\n");
    SuricataRuleset ruleset = ruleset(in);

    ruleset.checkImports();

    assertThat(ruleset.status().importError()).isEqualTo("the bundle has no rules");
    assertThat(ruleset.active().source()).isEqualTo("built-in");
  }

  private SuricataRuleset ruleset(Path importDir) {
    SuricataRuleset r = new SuricataRuleset(new SuricataEngine());
    ReflectionTestUtils.setField(r, "importDir", importDir.toString());
    ReflectionTestUtils.setField(r, "workDir", tmp.resolve("work").toString());
    ReflectionTestUtils.setField(r, "staleDays", 30);
    ReflectionTestUtils.setField(r, "validateTimeoutSeconds", 60);
    return r;
  }
}
