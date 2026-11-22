/**
 * How a TCP connection went (#1233), read from its handshake by the backend parser. One place for
 * the words, so the detail view and the filter say the same thing.
 */
export const CONNECTION_OUTCOMES = ['ANSWERED', 'NO_ANSWER', 'REJECTED', 'UNKNOWN'] as const;

/** Short labels for the filter pills. */
export const CONNECTION_OUTCOME_LABELS: Record<string, string> = {
  ANSWERED: 'Answered',
  NO_ANSWER: 'No answer',
  REJECTED: 'Refused',
  UNKNOWN: 'Unknown',
};

/** The sentence shown on one conversation. */
export const CONNECTION_OUTCOME_WORDS: Record<string, string> = {
  ANSWERED: 'Answered: the server accepted the connection',
  NO_ANSWER: 'No answer: the SYNs got no reply',
  REJECTED: 'Refused: the server answered with a reset',
};
