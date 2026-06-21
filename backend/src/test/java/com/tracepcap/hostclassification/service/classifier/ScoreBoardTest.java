package com.tracepcap.hostclassification.service.classifier;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class ScoreBoardTest {

  @Test
  void winner_returnsHighestScoringType() {
    ScoreBoard board = new ScoreBoard();
    board.add(DeviceTypes.SERVER, 20, "a");
    board.add(DeviceTypes.ROUTER, 35, "b");
    board.add(DeviceTypes.SERVER, 10, "c"); // SERVER → 30

    assertThat(board.winner(DeviceTypes.UNKNOWN)).isEqualTo(DeviceTypes.ROUTER);
  }

  @Test
  void winner_fallsBackWhenNothingScored() {
    assertThat(new ScoreBoard().winner(DeviceTypes.UNKNOWN)).isEqualTo(DeviceTypes.UNKNOWN);
  }

  @Test
  void add_ignoresZeroWeightAndNullType() {
    ScoreBoard board = new ScoreBoard();
    board.add(DeviceTypes.SERVER, 0, "zero");
    board.add(null, 50, "null");

    assertThat(board.winner(DeviceTypes.UNKNOWN)).isEqualTo(DeviceTypes.UNKNOWN);
    assertThat(board.scores()).isEmpty();
  }

  @Test
  void confidence_scalesWithMargin() {
    ScoreBoard board = new ScoreBoard();
    board.add(DeviceTypes.DNS_SERVER, 60, "x");
    board.add(DeviceTypes.SERVER, 0, "y"); // ignored (zero), so margin is 60 over nothing

    // margin 60 with marginForFull 60 → 100%
    assertThat(board.confidence(60)).isEqualTo(100);
  }

  @Test
  void confidence_smallMarginIsLow() {
    ScoreBoard board = new ScoreBoard();
    board.add(DeviceTypes.SERVER, 35, "a");
    board.add(DeviceTypes.ROUTER, 30, "b"); // margin 5

    assertThat(board.confidence(60)).isLessThan(20);
  }

  @Test
  void reasonsFor_returnsContributingReasonsInOrder() {
    ScoreBoard board = new ScoreBoard();
    board.add(DeviceTypes.ROUTER, 20, "first");
    board.add(DeviceTypes.ROUTER, 15, "second");

    assertThat(board.reasonsFor(DeviceTypes.ROUTER)).containsExactly("first", "second");
  }
}
