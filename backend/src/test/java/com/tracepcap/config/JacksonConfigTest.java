package com.tracepcap.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.core.exc.StreamConstraintsException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * Guards against a regression of #792: Jackson's default 20MB max-string-length
 * (StreamReadConstraints) rejected report-generation requests carrying a base64-encoded topology
 * diagram once the capture was large enough, with the request failing before it reached the
 * controller.
 */
class JacksonConfigTest {

  // One character past jackson-databind's compiled-in default (StreamReadConstraints.DEFAULT_MAX_STRING_LEN).
  private static final int OVER_JACKSON_DEFAULT = 20_000_001;

  private static String jsonWithStringOfLength(int length) {
    return "{\"value\":\"" + "a".repeat(length) + "\"}";
  }

  @Test
  void unconfiguredObjectMapperRejectsAStringPastTheDefaultLimit() {
    ObjectMapper mapper = new ObjectMapper();
    String json = jsonWithStringOfLength(OVER_JACKSON_DEFAULT);

    assertThatThrownBy(() -> mapper.readValue(json, Map.class))
        .isInstanceOf(StreamConstraintsException.class);
  }

  @Test
  void customizedObjectMapperAcceptsAStringPastTheDefaultLimit() throws Exception {
    JacksonConfig config = new JacksonConfig();
    ReflectionTestUtils.setField(config, "maxStringLength", 52_428_800);

    Jackson2ObjectMapperBuilder builder = new Jackson2ObjectMapperBuilder();
    config.streamReadConstraintsCustomizer().customize(builder);
    ObjectMapper mapper = builder.build();

    String json = jsonWithStringOfLength(OVER_JACKSON_DEFAULT);

    Map<?, ?> parsed = (Map<?, ?>) mapper.readValue(json, Map.class);

    assertThat(((String) parsed.get("value"))).hasSize(OVER_JACKSON_DEFAULT);
  }

  @Test
  void customizedObjectMapperStillRejectsPastItsOwnConfiguredLimit() {
    JacksonConfig config = new JacksonConfig();
    ReflectionTestUtils.setField(config, "maxStringLength", 100);

    Jackson2ObjectMapperBuilder builder = new Jackson2ObjectMapperBuilder();
    config.streamReadConstraintsCustomizer().customize(builder);
    ObjectMapper mapper = builder.build();

    String json = jsonWithStringOfLength(101);

    assertThatThrownBy(() -> mapper.readValue(json, Map.class))
        .isInstanceOf(StreamConstraintsException.class);
  }
}
