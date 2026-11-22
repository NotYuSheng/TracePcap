package com.tracepcap.knowledge.contributor;

import com.tracepcap.analysis.spi.ConversationLookup.ConversationFacts;
import com.tracepcap.common.net.IpLocality;
import com.tracepcap.extraction.spi.ExtractedFileLookup;
import com.tracepcap.extraction.spi.ExtractedFileLookup.ExtractedFileFacts;
import com.tracepcap.knowledge.spi.CaseKnowledgeBuilder;
import com.tracepcap.knowledge.spi.EntityRef;
import com.tracepcap.knowledge.spi.Finding;
import com.tracepcap.knowledge.spi.Grade;
import com.tracepcap.knowledge.spi.KnowledgeContext;
import com.tracepcap.knowledge.spi.KnowledgeContributor;
import com.tracepcap.knowledge.spi.Severity;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Component;

/**
 * Posts a {@code download} finding for each risky file (an executable, script, archive or
 * installer) a host fetched from outside the network over a real transfer. Answer keys list these
 * with their hashes ("Downloaded DLL file SHA256 hash: …"), and they are the payloads an analyst
 * exports and checks. A file carved from raw bytes is never one: those are guesses, often false.
 * Operating-system update servers are left out; everything else is listed for review, with no
 * claim that the file is malicious.
 */
@Component
public class DownloadContributor implements KnowledgeContributor {

  public static final String DOWNLOAD = "download";

  /** Types worth an analyst's look when they arrive from outside. */
  private static final Pattern RISKY_TYPE =
      Pattern.compile(
          "msdownload|x-dosexec|executable|x-msi|java-archive|zip|x-rar|x-7z|javascript|vbscript"
              + "|powershell|x-bat|hta|iso9660|x-sh",
          Pattern.CASE_INSENSITIVE);

  /** Windows/Defender/Office update hosts: routine, signed, and plentiful. */
  private static final Pattern OS_UPDATE_HOST =
      Pattern.compile(
          "(^|\\.)(windowsupdate\\.com|update\\.microsoft\\.com|delivery\\.mp\\.microsoft\\.com"
              + "|download\\.microsoft\\.com|officecdn\\.microsoft\\.com)$",
          Pattern.CASE_INSENSITIVE);

  /** Looked up when needed: a context without extraction (a test, a slice) still works. */
  private final ObjectProvider<ExtractedFileLookup> files;

  public DownloadContributor(ObjectProvider<ExtractedFileLookup> files) {
    this.files = files;
  }

  @Override
  public String name() {
    return "downloads";
  }

  @Override
  public void contribute(KnowledgeContext context, CaseKnowledgeBuilder board) {
    ExtractedFileLookup lookup = files.getIfAvailable();
    if (lookup == null) return;
    List<ExtractedFileFacts> all = lookup.extractedFiles(context.fileId());
    if (all.isEmpty()) return;
    Map<UUID, ConversationFacts> convs =
        context.conversationFacts().stream()
            .collect(Collectors.toMap(ConversationFacts::id, Function.identity(), (a, b) -> a));

    for (ExtractedFileFacts f : all) {
      if (f.skipped() || !f.realTransfer() || f.sha256() == null) continue;
      if (f.mimeType() == null || !RISKY_TYPE.matcher(f.mimeType()).find()) continue;
      ConversationFacts conv = f.conversationId() == null ? null : convs.get(f.conversationId());
      if (conv == null) continue;
      String src = conv.flow().srcIp();
      String dst = conv.flow().dstIp();
      if (src == null || dst == null || IpLocality.isLocal(src) == IpLocality.isLocal(dst)) continue;
      String host = IpLocality.isLocal(src) ? src : dst;
      String external = IpLocality.isLocal(src) ? dst : src;
      String serverName = conv.tls() == null ? null : conv.tls().hostname();
      if (serverName != null && OS_UPDATE_HOST.matcher(serverName.trim()).find()) continue;

      Map<String, Object> attrs = new LinkedHashMap<>();
      attrs.put("host", host);
      attrs.put("external", external);
      if (serverName != null && !serverName.isBlank()) attrs.put("serverName", serverName);
      attrs.put("name", f.filename());
      attrs.put("mimeType", f.mimeType());
      if (f.size() != null) attrs.put("size", f.size());
      attrs.put("sha256", f.sha256().toLowerCase(Locale.ROOT));
      if (conv.flow().startTime() != null) attrs.put("at", TrafficContributor.utc(conv.flow().startTime()));

      board.addFinding(
          new Finding(
              DOWNLOAD,
              host + " downloaded " + f.filename() + " from " + (serverName != null ? serverName : external),
              Severity.MEDIUM,
              Grade.MEASURED,
              name(),
              List.of(EntityRef.host(host), EntityRef.external(external)),
              List.of(conv.id().toString()),
              attrs));
    }
  }
}
