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
    // At most MAX_PER_SERVER files per host and server, the largest; the rest as one line, so one
    // chatty server (a ClickFix C2 answering every poll with a file) can't flood the answers.
    Map<String, List<Finding>> byServer = new LinkedHashMap<>();
    bySha.values().forEach(f -> byServer
        .computeIfAbsent(f.attributes().get("host") + ">" + f.attributes().get("external"), k -> new ArrayList<>())
        .add(f));
    List<Answer> answers = new ArrayList<>();
    byServer.values().forEach(files -> {
      files.sort(java.util.Comparator.comparingLong(
          (Finding f) -> f.attributes().get("size") instanceof Number n ? n.longValue() : 0L).reversed());
      files.stream().limit(MAX_PER_SERVER).forEach(f -> answers.add(answerFor(f)));
      if (files.size() > MAX_PER_SERVER) {
        Finding first = files.get(0);
        int more = files.size() - MAX_PER_SERVER;
        answers.add(
            new Answer(
                QUESTION,
                first.attributes().get("host") + " downloaded " + more + " more file" + (more == 1 ? "" : "s")
                    + " from " + first.attributes().get("external") + " (smaller ones; see the Files tab)",
                Grade.MEASURED,
                first.concerns(),
                List.of(more + " more file" + (more == 1 ? "" : "s") + " from " + first.attributes().get("external")),
                new LinkedHashMap<>(Map.of("host", first.attributes().get("host"),
                    "external", first.attributes().get("external"), "more", more))));
      }
    });
    return answers;
  }

  static final int MAX_PER_SERVER = 3;

  /** One downloaded file: what, how big, from where, and its SHA-256. */
  private static Answer answerFor(Finding f) {
    Map<String, Object> a = f.attributes();
    Object size = a.get("size");
    String from =
        a.get("url") != null
            ? a.get("url") + " (" + a.get("external") + ")"
            : String.valueOf(a.getOrDefault("serverName", a.get("external")));
    return new Answer(
        QUESTION,
        a.get("host") + " downloaded " + a.get("name")
            + " (" + kindOf(String.valueOf(a.get("mimeType")), a.get("name"))
            + (size instanceof Number n ? ", " + human(n.longValue()) : "") + ") from " + from
            + ". SHA-256 " + a.get("sha256"),
        Grade.MEASURED,
        f.concerns(),
        List.of(f.summary()),
        new LinkedHashMap<>(a)).withDerivation(List.of(new com.tracepcap.knowledge.spi.Step(
            f.summary() + ", and its contents were hashed.", Derivations.RULE_DOWNLOAD, Grade.MEASURED,
            f.evidence())));
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

  /** A script's kind from its name, when its content was only typed as text. */
  static String kindOf(String mime, Object name) {
    String n = name == null ? "" : name.toString().toLowerCase(java.util.Locale.ROOT);
    if (n.endsWith(".ps1") || n.endsWith(".psm1")) return "PowerShell script";
    if (n.endsWith(".js") || n.endsWith(".jse")) return "JScript";
    if (n.endsWith(".vbs") || n.endsWith(".vbe")) return "VBScript";
    if (n.endsWith(".hta")) return "HTML application";
    if (n.endsWith(".bat") || n.endsWith(".cmd")) return "batch script";
    return kind(mime);
  }

  static String human(long bytes) {
    if (bytes >= 1_000_000) return String.format("%.1f MB", bytes / 1_000_000.0);
    if (bytes >= 1_000) return String.format("%.0f KB", bytes / 1_000.0);
    return bytes + " bytes";
  }
}
