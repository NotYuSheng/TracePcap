package com.tracepcap.common.settings;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

/** The System settings view (#915 phase 1). */
class SystemSettingsCatalogTest {

  @Test
  void everyEnvPlaceholderInApplicationYmlIsListed() throws Exception {
    // A new ${ENV} in application.yml must appear in the settings view too, or the view quietly
    // stops showing "everything".
    String yml = Files.readString(Path.of("src/main/resources/application.yml"));
    Matcher m = Pattern.compile("\\$\\{([A-Z][A-Z0-9_]+)").matcher(yml);
    Set<String> placeholders = new java.util.TreeSet<>();
    while (m.find()) placeholders.add(m.group(1));
    Set<String> listed =
        SystemSettingsCatalog.ENTRIES.stream().map(SystemSettingsCatalog.Entry::env).collect(Collectors.toSet());

    assertThat(listed).containsAll(placeholders);
  }

  @Test
  void secretsAreReportedAsSetButNeverReturned() {
    MockEnvironment env = new MockEnvironment().withProperty("llm.api.api-key", "sk-real-key");
    SystemSettingDto key =
        new SystemSettingsService(env).list().stream()
            .filter(s -> s.getKey().equals("LLM_API_KEY")).findFirst().orElseThrow();

    assertThat(key.isSecret()).isTrue();
    assertThat(key.isSet()).isTrue();
    assertThat(key.getValue()).isNull();
    assertThat(key.getDefaultValue()).isNull();
  }

  @Test
  void showsTheEffectiveValue_fallingBackToTheDefault() {
    MockEnvironment env = new MockEnvironment().withProperty("tracepcap.cleanup.retention-hours", "48");
    var byKey = new SystemSettingsService(env).list().stream()
        .collect(Collectors.toMap(SystemSettingDto::getKey, s -> s));

    assertThat(byKey.get("FILE_RETENTION_HOURS").getValue()).isEqualTo("48");
    assertThat(byKey.get("FILE_RETENTION_HOURS").getDefaultValue()).isEqualTo("12");
    assertThat(byKey.get("HTTP_MIN_REQUESTS").getValue()).isEqualTo("20"); // unset: the default
  }

  @Test
  void nothingIsEditableInPhaseOne_andEverySettingSaysWhy() {
    var all = new SystemSettingsService(new MockEnvironment()).list();

    assertThat(all).allSatisfy(s -> {
      assertThat(s.isEditable()).isFalse();
      assertThat(s.getLockedReason()).contains(s.getKey());
    });
    assertThat(all).extracting(SystemSettingDto::getGroup)
        .contains("INFRASTRUCTURE", "MEMORY", "POLICY");
  }
}
