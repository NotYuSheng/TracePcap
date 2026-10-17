package com.tracepcap.knowledge.question;

import com.tracepcap.knowledge.spi.Answer;
import com.tracepcap.knowledge.spi.CaseKnowledge;
import com.tracepcap.knowledge.spi.Relationship;
import com.tracepcap.knowledge.spi.StandardQuestion;
import java.util.LinkedHashMap;
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
        .map(signedIn -> toAnswer(board, signedIn))
        .toList();
  }

  private Answer toAnswer(CaseKnowledge board, Relationship signedIn) {
    String host = signedIn.from().key();
    String user = signedIn.to().key();
    // The person's real name, if a directory lookup named it (posted on the USER entity by the
    // host-identity contributor) — "ccollier (Clark Collier)" rather than the principal alone.
    String realName =
        board.entity(signedIn.to())
            .map(e -> e.attributes().get("realName"))
            .filter(v -> v != null && !v.toString().isBlank())
            .map(Object::toString)
            .orElse(null);
    String who = realName != null ? user + " (" + realName + ")" : user;

    Map<String, Object> attrs = new LinkedHashMap<>();
    attrs.put("user", user);
    attrs.put("host", host);
    if (realName != null) attrs.put("realName", realName);

    return new Answer(
        QUESTION,
        who + " signed in on " + host,
        signedIn.grade(),
        List.of(signedIn.to(), signedIn.from()),
        List.of("from " + signedIn.source() + " (" + signedIn.grade() + ")"),
        attrs);
  }
}
