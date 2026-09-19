package com.tracepcap.knowledge.question;

import com.tracepcap.knowledge.spi.Answer;
import com.tracepcap.knowledge.spi.CaseKnowledge;
import com.tracepcap.knowledge.spi.Relationship;
import com.tracepcap.knowledge.spi.StandardQuestion;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * "Who is signed in, and where?" — each {@code signed-in-as} edge on the board becomes an answer,
 * carrying the edge's own grade (Kerberos sign-ins are MEASURED, LDAP-only REPORTED), so the
 * confidence of "who was at the keyboard" is explicit rather than assumed.
 */
@Component
public class SignedInUserQuestion implements StandardQuestion {

  static final String QUESTION = "signed-in-user";

  @Override
  public String question() {
    return QUESTION;
  }

  @Override
  public List<Answer> answer(CaseKnowledge board) {
    return board.relationshipsWithPredicate("signed-in-as").stream()
        .map(this::toAnswer)
        .toList();
  }

  private Answer toAnswer(Relationship signedIn) {
    String host = signedIn.from().key();
    String user = signedIn.to().key();
    return new Answer(
        QUESTION,
        user + " signed in on " + host,
        signedIn.grade(),
        List.of(signedIn.to(), signedIn.from()),
        List.of("from " + signedIn.source() + " (" + signedIn.grade() + ")"),
        Map.of("user", user, "host", host));
  }
}
