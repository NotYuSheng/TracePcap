package com.tracepcap.knowledge.question;

import com.tracepcap.knowledge.contributor.KerberosContributor;
import com.tracepcap.knowledge.contributor.TrafficContributor;
import com.tracepcap.knowledge.spi.Answer;
import com.tracepcap.knowledge.spi.CaseKnowledge;
import com.tracepcap.knowledge.spi.Finding;
import com.tracepcap.knowledge.spi.Grade;
import com.tracepcap.knowledge.spi.StandardQuestion;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * "Is someone attacking accounts or tickets?" (#1267). One answer per Kerberos finding: a host
 * guessing passwords across many accounts (spraying, or enumerating which accounts exist), or a
 * domain controller handing out a weak ticket while it uses AES elsewhere (Kerberoasting, Skeleton
 * Key).
 */
@Component
public class KerberosAttackQuestion implements StandardQuestion {

  static final String QUESTION = "kerberos-attack";

  @Override
  public String question() {
    return QUESTION;
  }

  @Override
  public List<Answer> answer(CaseKnowledge board) {
    List<Answer> answers = new ArrayList<>();
    for (Finding f : board.findingsOfCategory(KerberosContributor.KERBEROS_ATTACK)) {
      Map<String, Object> a = f.attributes();
      Map<String, Object> attrs = new LinkedHashMap<>();
      for (String k : List.of("technique", "client", "kdc", "firstSeen")) {
        if (a.get(k) != null) attrs.put(k, a.get(k));
      }
      List<String> basis = new ArrayList<>();
      if (a.get("operations") instanceof List<?> l) l.forEach(x -> basis.add(String.valueOf(x)));
      answers.add(new Answer(QUESTION, headline(a), Grade.MEASURED, f.concerns(), basis, attrs));
    }
    return answers;
  }

  static String headline(Map<String, Object> a) {
    String client = String.valueOf(a.get("client")), kdc = String.valueOf(a.get("kdc"));
    String when = a.get("firstSeen") != null
        ? " (from " + TrafficContributor.readable(a.get("firstSeen")) + ")" : "";
    if (KerberosContributor.PASSWORD_GUESSING.equals(a.get("technique"))) {
      int wrong = size(a.get("wrongPassword")), unknown = size(a.get("noSuchAccount"));
      int most = a.get("mostWrongForOneAccount") instanceof Integer i ? i : 0;
      String what = wrong + unknown >= 5
          ? (unknown > wrong
              ? "That is user enumeration (finding which accounts exist), or password spraying."
              : "That is password spraying.")
          : "That is password guessing against one account.";
      return client + " failed to sign in at the domain controller " + kdc + when + ": "
          + (wrong > 0 ? "a wrong password for " + wrong + " account" + (wrong == 1 ? "" : "s") : "")
          + (wrong > 0 && unknown > 0 ? " and " : "")
          + (unknown > 0 ? unknown + " account name" + (unknown == 1 ? "" : "s") + " that don't exist" : "")
          + (most >= 10 ? ", " + most + " wrong passwords for one" : "")
          + ". " + what;
    }
    boolean services = size(a.get("services")) > 0, signIns = size(a.get("signIns")) > 0;
    return "The domain controller " + kdc + " gave " + client + " " + (services && signIns ? "tickets"
        : services ? "service tickets" : "a sign-in ticket") + " encrypted with RC4 or DES" + when
        + ", though it uses AES elsewhere in this capture. "
        + (services ? "Weak service tickets are what Kerberoasting asks for, to crack offline. " : "")
        + (signIns ? "A weak sign-in ticket is what Skeleton Key forces. " : "")
        + "Check what asked for them.";
  }

  private static int size(Object o) {
    return o instanceof List<?> l ? l.size() : 0;
  }
}
