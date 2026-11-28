package com.tracepcap.common.db;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;

class InBatchesTest {

  @Test
  void keysPastTheBatchSizeGoOutInBatchesAndComeBackInOrder() {
    List<Integer> sizes = new ArrayList<>();
    var keys = new LinkedHashSet<>(IntStream.range(0, 2 * InBatches.SIZE + 1).boxed().toList());

    List<Integer> out = InBatches.of(keys, batch -> { sizes.add(batch.size()); return batch; });

    assertThat(sizes).containsExactly(InBatches.SIZE, InBatches.SIZE, 1);
    assertThat(out).containsExactlyElementsOf(keys);
  }

  @Test
  void noKeysRunNoQuery() {
    assertThat(InBatches.<Integer, Integer>of(List.of(), b -> { throw new AssertionError(); })).isEmpty();
    assertThat(InBatches.<Integer, Integer>of(null, b -> { throw new AssertionError(); })).isEmpty();
  }
}
