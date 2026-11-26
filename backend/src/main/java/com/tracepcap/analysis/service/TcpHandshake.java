package com.tracepcap.analysis.service;

/**
 * How a TCP connection went (#1233), read off the handshake as the packets go by: was it answered,
 * left unanswered, or refused? This is the same question Zeek's {@code conn_state} answers, cut
 * down to what an analyst acts on: scans and dead C2 servers show up as connections nobody
 * answered or that were refused.
 *
 * <p>Deliberately not a "reset" outcome: on a real Windows-domain capture 82 of 210 connections
 * ended in a reset, almost all of them ordinary, so it would label normal traffic.
 *
 * <p>Unknown (null) when the capture never saw the opening SYN: it joined mid-connection.
 */
public final class TcpHandshake {

  /** Stored in {@code conversations.connection_outcome}. */
  public enum Outcome {
    /** The server replied: SYN+ACK seen, or traffic only an open connection carries. */
    ANSWERED,
    /** SYNs went out and nothing came back. */
    NO_ANSWER,
    /** The server refused: it sent a reset instead of SYN+ACK. */
    REJECTED
  }

  private String opener;
  private boolean synAck;
  private boolean openerAckedOrSentData;
  private boolean responderReplied;
  private boolean responderReset;

  /** One packet of the connection, from {@code srcIp:srcPort}, with its SYN/ACK/RST bits. */
  public void observe(String srcIp, Integer srcPort, boolean syn, boolean ack, boolean rst) {
    String from = srcIp + ":" + srcPort;
    if (syn && !ack && opener == null) opener = from;
    if (syn && ack) synAck = true;
    if (opener == null) return;
    boolean fromOpener = opener.equals(from);
    if (fromOpener) {
      // A plain ACK or data from the opener only happens once the handshake completed, so it
      // counts as answered even when the capture saw only this direction (asymmetric routing,
      // a span port on one side).
      if (!syn && !rst && ack) openerAckedOrSentData = true;
    } else if (rst) {
      responderReset = true;
    } else {
      responderReplied = true;
    }
  }

  /** The outcome so far, or null when the opening SYN wasn't seen. */
  public Outcome outcome() {
    if (opener == null) return null;
    if (synAck || openerAckedOrSentData || responderReplied) return Outcome.ANSWERED;
    if (responderReset) return Outcome.REJECTED;
    return Outcome.NO_ANSWER;
  }
}
