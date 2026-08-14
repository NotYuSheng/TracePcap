package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Packets share the strings they repeat (#779).
 *
 * <p>A capture has a few hundred distinct addresses and millions of packets, and {@code split()}
 * returns a fresh String for every field of every packet. At ~776 bytes per PacketInfo, 1.7M
 * packets need ~1.26 GB against a 1 GB heap — the OutOfMemoryError that made a 468 MB capture
 * unanalysable.
 *
 * <p>Identity is the assertion, not equality: two equal Strings that are separate objects are
 * exactly the waste being removed, and {@code isEqualTo} would pass while the bug remained.
 */
class PacketStringPoolingTest {

  private static String pooled(Map<String, String> pool, String value) {
    try {
      Method m = PcapParserService.class.getDeclaredMethod("pooled", Map.class, String.class);
      m.setAccessible(true);
      return (String) m.invoke(null, pool, value);
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException("pooled() changed — update this test", e);
    }
  }

  @Test
  void repeatedValuesBecomeTheSameObject() {
    Map<String, String> pool = new HashMap<>();
    // Deliberately not literals: those would already be interned by the compiler and the test
    // would pass without the pool doing anything.
    String first = new String("192.168.1.1");
    String second = new String("192.168.1.1");

    assertThat(pooled(pool, first)).isSameAs(pooled(pool, second));
  }

  @Test
  void distinctValuesStayDistinct() {
    Map<String, String> pool = new HashMap<>();

    assertThat(pooled(pool, new String("10.0.0.1")))
        .isNotSameAs(pooled(pool, new String("10.0.0.2")));
    assertThat(pooled(pool, new String("10.0.0.1"))).isEqualTo("10.0.0.1");
  }

  @Test
  void nullPassesThroughRatherThanBeingPooled() {
    Map<String, String> pool = new HashMap<>();

    assertThat(pooled(pool, null)).isNull();
    assertThat(pool).isEmpty();
  }

  @Test
  void thePoolHoldsOneEntryPerDistinctValueNotOnePerPacket() {
    // The property that bounds the saving: a million packets across ten addresses must cost ten
    // strings, not a million.
    Map<String, String> pool = new HashMap<>();
    for (int i = 0; i < 10_000; i++) {
      pooled(pool, new String("10.0.0." + (i % 10)));
      pooled(pool, new String("TCP"));
    }

    assertThat(pool).hasSize(11);
  }
}
