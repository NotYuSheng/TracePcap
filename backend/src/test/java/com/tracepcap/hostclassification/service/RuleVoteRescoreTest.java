package com.tracepcap.hostclassification.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.analysis.spi.ClassificationHint;
import com.tracepcap.analysis.spi.HostClassifier.Board;
import com.tracepcap.hostclassification.service.classifier.ScoreBoard;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

/** Re-scoring a stored board after a rule's device-type vote changed (#925). */
class RuleVoteRescoreTest {

  // The re-score path uses none of the classifier's collaborators.
  private final DeviceClassifierService classifier = Mockito.mock(DeviceClassifierService.class, Mockito.CALLS_REAL_METHODS);

  private static final ClassificationHint RTSP_40 = new ClassificationHint("rtsp", "CCTV Camera", 40);

  /** TTL evidence for SERVER (30) and a rule vote for "CCTV Camera" (40). */
  private static Board board() {
    ScoreBoard b = new ScoreBoard();
    b.add("SERVER", 30, "TTL 64");
    b.add("CCTV Camera", 40, "Custom rule \"rtsp\" → CCTV Camera +40");
    return new Board(b.scores(), b.allReasons(), List.of(RTSP_40));
  }

  @Test
  void theSameVotesChangeNothing() {
    assertThat(classifier.rescoreRuleVotes(board(), List.of(RTSP_40))).isEmpty();
  }

  @Test
  void aWeakerVoteLetsTheOtherEvidenceWin_andTheOldReasonGoes() {
    var v = classifier.rescoreRuleVotes(board(), List.of(new ClassificationHint("rtsp", "CCTV Camera", 10))).orElseThrow();
    assertThat(v.deviceType()).isEqualTo("SERVER");
    assertThat(v.board().scores()).containsEntry("SERVER", 30).containsEntry("CCTV Camera", 10);
    assertThat(v.board().reasons().get("CCTV Camera")).containsExactly("Custom rule \"rtsp\" → CCTV Camera +10");
    assertThat(v.runnerUpType()).isEqualTo("CCTV Camera");
    assertThat(v.confidence()).isBetween(0, 100);
  }

  @Test
  void aRemovedVoteIsTakenBackEntirely() {
    var v = classifier.rescoreRuleVotes(board(), List.of()).orElseThrow();
    assertThat(v.deviceType()).isEqualTo("SERVER");
    assertThat(v.board().scores()).doesNotContainKey("CCTV Camera");
    assertThat(v.board().ruleVotes()).isEmpty();
  }

  @Test
  void aStrongerVoteForAnotherTypeWins() {
    var v = classifier.rescoreRuleVotes(board(), List.of(new ClassificationHint("rtsp", "PLC", 90))).orElseThrow();
    assertThat(v.deviceType()).isEqualTo("PLC");
  }

  @Test
  void noStoredBoardMeansNothingToRescore() {
    assertThat(classifier.rescoreRuleVotes(new Board(null, null, List.of()), List.of(RTSP_40))).isEmpty();
  }
}
