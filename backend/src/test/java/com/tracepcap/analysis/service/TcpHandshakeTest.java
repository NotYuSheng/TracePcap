package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.analysis.service.TcpHandshake.Outcome;
import org.junit.jupiter.api.Test;

class TcpHandshakeTest {

  private static final String C = "10.0.0.5";
  private static final String S = "203.0.113.9";

  private static TcpHandshake h() {
    return new TcpHandshake();
  }

  @Test
  void synThenSynAck_isAnswered() {
    TcpHandshake h = h();
    h.observe(C, 50000, true, false, false);
    h.observe(S, 443, true, true, false);
    h.observe(C, 50000, false, true, false);
    assertThat(h.outcome()).isEqualTo(Outcome.ANSWERED);
  }

  @Test
  void answeredThenReset_staysAnswered() {
    // 82 of 210 connections on a real capture ended in a reset; that's not a refusal.
    TcpHandshake h = h();
    h.observe(C, 50000, true, false, false);
    h.observe(S, 443, true, true, false);
    h.observe(S, 443, false, true, true);
    assertThat(h.outcome()).isEqualTo(Outcome.ANSWERED);
  }

  @Test
  void retransmittedSynsAndNothingBack_isNoAnswer() {
    TcpHandshake h = h();
    h.observe(C, 50000, true, false, false);
    h.observe(C, 50000, true, false, false);
    h.observe(C, 50000, true, false, false);
    assertThat(h.outcome()).isEqualTo(Outcome.NO_ANSWER);
  }

  @Test
  void clientGivingUpWithItsOwnReset_isStillNoAnswer() {
    TcpHandshake h = h();
    h.observe(C, 50000, true, false, false);
    h.observe(C, 50000, false, true, true);
    assertThat(h.outcome()).isEqualTo(Outcome.NO_ANSWER);
  }

  @Test
  void resetFromTheServerInsteadOfSynAck_isRejected() {
    TcpHandshake h = h();
    h.observe(C, 50000, true, false, false);
    h.observe(S, 22, false, true, true);
    assertThat(h.outcome()).isEqualTo(Outcome.REJECTED);
  }

  @Test
  void onlyTheClientDirectionCaptured_butItSendsData_isAnswered() {
    // Asymmetric routing / a one-sided span port: the SYN+ACK is missing, but a plain ACK or data
    // from the client only happens once the handshake completed.
    TcpHandshake h = h();
    h.observe(C, 50000, true, false, false);
    h.observe(C, 50000, false, true, false);
    assertThat(h.outcome()).isEqualTo(Outcome.ANSWERED);
  }

  @Test
  void synAckMissedButServerSentData_isAnswered() {
    TcpHandshake h = h();
    h.observe(C, 50000, true, false, false);
    h.observe(S, 443, false, true, false);
    assertThat(h.outcome()).isEqualTo(Outcome.ANSWERED);
  }

  @Test
  void joinedMidConnection_isUnknown() {
    TcpHandshake h = h();
    h.observe(C, 50000, false, true, false);
    h.observe(S, 443, false, true, false);
    h.observe(S, 443, false, true, true);
    assertThat(h.outcome()).isNull();
  }
}
