package com.tracepcap.knowledge.question;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class EvidenceTest {

  @Test
  void repeatsBecomeOneLineWithACount_inFirstSeenOrder() {
    List<String> lines = new ArrayList<>();
    for (int i = 0; i < 303; i++) lines.add("ET MALWARE BadSpace/WarmCookie CnC Activity (GET) M1 (sid:2052557 sev:1)");
    lines.add(1, "ET MALWARE W32/Badspace.Backdoor CnC Activity (POST) (sid:2052558 sev:1)");
    assertThat(Evidence.collapse(lines))
        .containsExactly(
            "ET MALWARE BadSpace/WarmCookie CnC Activity (GET) M1 (sid:2052557 sev:1) (×303)",
            "ET MALWARE W32/Badspace.Backdoor CnC Activity (POST) (sid:2052558 sev:1)");
  }
}
