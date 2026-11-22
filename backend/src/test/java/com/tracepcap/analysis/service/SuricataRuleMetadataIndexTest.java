package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.analysis.spi.IdsRuleMetadata.RuleInfo;
import org.junit.jupiter.api.Test;

/** Rule lines as they appear in ET Open (trimmed to the keywords that matter here). */
class SuricataRuleMetadataIndexTest {

  @Test
  void readsTheMalwareFamilyTag_withUnderscoresAsSpaces() {
    assertThat(SuricataRuleMetadataIndex.parseLine(
            "alert http $HOME_NET any -> $EXTERNAL_NET any (msg:\"ET MALWARE Lumma Stealer Victim Fingerprinting Activity\"; "
                + "metadata:attack_target Client_Endpoint, malware_family Lumma_Stealer, signature_severity Critical; sid:2066606; rev:1;)"))
        .isEqualTo(new RuleInfo(true, "Lumma Stealer"));
  }

  @Test
  void aRuleWithMetadataButNoFamily_namesNone() {
    assertThat(SuricataRuleMetadataIndex.parseLine(
            "alert http any any -> any any (msg:\"ET MALWARE W32/Badspace.Backdoor CnC Activity (POST)\"; "
                + "metadata:attack_target Client_Endpoint, signature_severity Major; sid:2052558; rev:1;)"))
        .isEqualTo(new RuleInfo(true, null));
  }

  @Test
  void commentsAndDisabledRulesAreSkipped_andRulesWithoutMetadataSaySo() {
    assertThat(SuricataRuleMetadataIndex.parseLine("# a comment")).isNull();
    assertThat(SuricataRuleMetadataIndex.parseLine("#alert tcp any any -> any any (msg:\"x\"; sid:1;)")).isNull();
    assertThat(SuricataRuleMetadataIndex.parseLine("alert tcp any any -> any any (msg:\"x\"; sid:1;)"))
        .isEqualTo(new RuleInfo(false, null));
  }
}
