package com.tracepcap.knowledge.question;

import com.tracepcap.knowledge.contributor.DownloadContributor;
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
 * "What did the host download?" Executables, scripts, archives and installers fetched from outside
 * over a real transfer, each with its SHA-256: what an incident report lists ("Downloaded DLL file
 * SHA256 hash: …") and what an analyst exports and checks. MEASURED, because the bytes were seen;
 * it says nothing about whether the file is malicious. One answer per distinct file.
 */
@Component
public class DownloadsQuestion implements StandardQuestion {

  static final String QUESTION = "downloads";

  @Override
  public String question() {
    return QUESTION;
  }

  @Override
  public List<Answer> answer(CaseKnowledge board) {
    Map<String, Finding> bySha = new LinkedHashMap<>();
    for (Finding f : board.findingsOfCategory(DownloadContributor.DOWNLOAD)) {
      Object sha = f.attributes().get("sha256");
      if (sha != null) bySha.putIfAbsent(sha.toString(), f);
    }
    List<Answer> answers = new ArrayList<>();
    bySha.forEach(
        (sha, f) -> {
          Map<String, Object> a = f.attributes();
          Object size = a.get("size");
          String from = a.get("url") != null
              ? a.get("url") + " (" + a.get("external") + ")"
              : String.valueOf(a.getOrDefault("serverName", a.get("external")));
          answers.add(
              new Answer(
                  QUESTION,
                  a.get("host") + " downloaded " + a.get("name") + " (" + kind(String.valueOf(a.get("mimeType")))
                      + (size instanceof Number n ? ", " + human(n.longValue()) : "") + ") from " + from
                      + ". SHA-256 " + sha,
                  Grade.MEASURED,
                  f.concerns(),
                  List.of(f.summary()),
                  new LinkedHashMap<>(a)));
        });
    return answers;
  }

  static String kind(String mime) {
    String m = mime.toLowerCase(java.util.Locale.ROOT);
    if (m.contains("msdownload") || m.contains("dosexec") || m.contains("executable")) return "Windows program or DLL";
    if (m.contains("x-msi")) return "Windows installer";
    if (m.contains("java-archive")) return "Java archive";
    if (m.contains("zip") || m.contains("rar") || m.contains("7z")) return "archive";
    if (m.contains("javascript") || m.contains("vbscript") || m.contains("powershell") || m.contains("x-bat")
        || m.contains("hta") || m.contains("x-sh")) return "script";
    if (m.contains("iso9660")) return "disk image";
    return mime;
  }

  static String human(long bytes) {
    if (bytes >= 1_000_000) return String.format("%.1f MB", bytes / 1_000_000.0);
    if (bytes >= 1_000) return String.format("%.0f KB", bytes / 1_000.0);
    return bytes + " bytes";
  }
}
