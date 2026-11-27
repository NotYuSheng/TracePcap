package com.tracepcap.knowledge.contributor;

import com.tracepcap.analysis.spi.ConversationLookup.ConversationFacts;
import com.tracepcap.common.net.LocalityRules;
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
          // "(?<!g)zip": application/zip, x-zip-compressed — not gzip, which is how web pages and
          // API responses are compressed (55 such "archives" from one ClickFix C2 in a holdout test).
          "msdownload|x-dosexec|executable|x-msi|java-archive|(?<!g)zip|x-rar|x-7z|javascript|vbscript"
              + "|powershell|x-bat|hta|iso9660|x-sh",
          Pattern.CASE_INSENSITIVE);

  /**
   * A risky file by its name, for what content detection can't tell: a PowerShell, JScript or batch
   * script is plain text (Tika says text/plain), so only its extension says what it is. The
   * 2025-01-22 fake software site's C2 served two .ps1 scripts this way.
   */
  private static final Pattern RISKY_NAME =
      Pattern.compile(
          "\\.(ps1|psm1|js|jse|vbs|vbe|hta|bat|cmd|wsf|wsh|lnk|scr|msi|exe|dll|jar|iso|img|zip|7z|rar)$",
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

  /** The file's name, or its URL's last path part, ends in a risky extension. */
  static boolean riskyName(ExtractedFileFacts f) {
    if (f.filename() != null && RISKY_NAME.matcher(f.filename().trim()).find()) return true;
    if (f.sourceUrl() == null) return false;
    try {
      String path = java.net.URI.create(f.sourceUrl().replace(" ", "%20")).getPath();
      return path != null && RISKY_NAME.matcher(path).find();
    } catch (Exception e) {
      return false;
    }
  }

  /** The host of "http://host:port/path", or null. */
  static String urlHost(String url) {
    if (url == null) return null;
    try {
      String h = java.net.URI.create(url.replace(" ", "%20")).getHost();
      return h == null || h.isBlank() ? null : h;
    } catch (Exception e) {
      return null;
    }
  }

  @Override
  public void contribute(KnowledgeContext context, CaseKnowledgeBuilder board) {
    LocalityRules local = context.locality();
    ExtractedFileLookup lookup = files.getIfAvailable();
    if (lookup == null) return;
    List<ExtractedFileFacts> all = lookup.extractedFiles(context.fileId());
    if (all.isEmpty()) return;
    Map<UUID, ConversationFacts> convs =
        context.conversationFacts().stream()
            .collect(Collectors.toMap(ConversationFacts::id, Function.identity(), (a, b) -> a));

    for (ExtractedFileFacts f : all) {
      if (f.skipped() || !f.realTransfer() || f.sha256() == null) continue;
      boolean riskyType = f.mimeType() != null && RISKY_TYPE.matcher(f.mimeType()).find();
      if (!riskyType && !riskyName(f)) continue;
      ConversationFacts conv = f.conversationId() == null ? null : convs.get(f.conversationId());
      if (conv == null) continue;
      String src = conv.flow().srcIp();
      String dst = conv.flow().dstIp();
      if (src == null || dst == null || local.isLocal(src) == local.isLocal(dst)) continue;
      String host = local.isLocal(src) ? src : dst;
      String external = local.isLocal(src) ? dst : src;
      String serverName = urlHost(f.sourceUrl());
      if (serverName == null && conv.tls() != null) serverName = conv.tls().hostname();
      if (serverName != null && OS_UPDATE_HOST.matcher(serverName.trim()).find()) continue;

      Map<String, Object> attrs = new LinkedHashMap<>();
      attrs.put("host", host);
      attrs.put("external", external);
      if (serverName != null && !serverName.isBlank()) attrs.put("serverName", serverName);
      attrs.put("name", f.filename());
      if (f.sourceUrl() != null) attrs.put("url", f.sourceUrl());
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
