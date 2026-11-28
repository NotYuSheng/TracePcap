package com.tracepcap.common.db;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;
import org.springframework.data.domain.Limit;

class InPagesTest {

  @Test
  void readsEveryRowAPageAtATimeAfterTheLastId() {
    List<Integer> rows = IntStream.range(0, 2 * InPages.SIZE + 3).boxed().toList();
    List<Integer> afters = new ArrayList<>();

    List<String> out = InPages.of(
        (Integer after, Limit limit) -> {
          afters.add(after);
          int from = after == null ? 0 : after + 1;
          return rows.subList(from, Math.min(rows.size(), from + limit.max()));
        },
        r -> r, r -> "row" + r, null, null);

    assertThat(out).hasSize(rows.size()).startsWith("row0").endsWith("row" + (rows.size() - 1));
    assertThat(afters).containsExactly(null, InPages.SIZE - 1, 2 * InPages.SIZE - 1);
  }

  @Test
  void anExactlyFullLastPageEndsOnTheEmptyOneAfterIt() {
    List<Integer> rows = IntStream.range(0, InPages.SIZE).boxed().toList();
    List<Integer> afters = new ArrayList<>();

    List<Integer> out = InPages.of(
        (Integer after, Limit limit) -> {
          afters.add(after);
          return after == null ? rows : List.of();
        },
        r -> r, r -> r, null, null);

    assertThat(out).hasSize(InPages.SIZE);
    assertThat(afters).containsExactly(null, InPages.SIZE - 1);
  }
}
