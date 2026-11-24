package com.tracepcap.knowledge.contributor;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Remote-admin tools as ET's INFO/POLICY rules name them: the list the remote-access answer and the
 * install-chain escalation share. ET files these tools' check-ins under INFO, not MALWARE, because
 * IT departments use them; the same tools are favourite RATs.
 */
public final class RemoteAccessTools {

  private RemoteAccessTools() {}

  private static final Map<String, String> TOOLS = new LinkedHashMap<>();

  static {
    TOOLS.put("netsupport", "NetSupport");
    TOOLS.put("anydesk", "AnyDesk");
    TOOLS.put("screenconnect", "ScreenConnect");
    TOOLS.put("connectwise control", "ScreenConnect");
    TOOLS.put("teamviewer", "TeamViewer");
    TOOLS.put("atera", "Atera");
    TOOLS.put("splashtop", "Splashtop");
    TOOLS.put("rustdesk", "RustDesk");
    TOOLS.put("supremo", "Supremo");
    TOOLS.put("remote utilities", "Remote Utilities");
    TOOLS.put("logmein", "LogMeIn");
    TOOLS.put("simplehelp", "SimpleHelp");
    TOOLS.put("meshcentral", "MeshCentral");
    TOOLS.put("action1", "Action1");
    TOOLS.put("tactical rmm", "Tactical RMM");
    TOOLS.put("kaseya", "Kaseya");
    TOOLS.put("zoho assist", "Zoho Assist");
    TOOLS.put("ninjaone", "NinjaOne");
    TOOLS.put("radmin", "Radmin");
    TOOLS.put("nomachine", "NoMachine");
  }

  /** nDPI's names for remote-control apps it recognises by itself (works with Suricata off). */
  private static final Map<String, String> NDPI_APPS =
      Map.of("teamviewer", "TeamViewer", "anydesk", "AnyDesk", "radmin", "Radmin", "nomachine", "NoMachine");

  /**
   * A tool's own vendor service, not a remote-control session: NetSupport's GeoLocation lookup to
   * geo.netsupportsoftware.com, licence and update checks. (A holdout capture showed one as
   * "NetSupport talking to 104.26.1.231".)
   */
  private static final Pattern VENDOR_SERVICE =
      Pattern.compile("GeoLocation|Geo Location|Lookup Request|License|Licence|Update Check|Version Check",
          Pattern.CASE_INSENSITIVE);

  /** The family name a tool's abuse goes by, where it has one; else "<tool> (unsanctioned use)". */
  private static final Map<String, String> RAT_NAMES = Map.of("NetSupport", "NetSupport RAT");

  private static final Pattern TOOL =
      Pattern.compile(
          "\\b(" + String.join("|", TOOLS.keySet().stream().map(Pattern::quote).toList()) + ")\\b",
          Pattern.CASE_INSENSITIVE);

  /** Rules about a name lookup: the far end is a resolver, not the tool's server. */
  private static final Pattern DNS_RULE =
      Pattern.compile("\\b(DNS (Lookup|Query)|in DNS)\\b", Pattern.CASE_INSENSITIVE);

  /**
   * The tool an IDS alert shows talking to its server, or null: none named, a DNS-lookup rule (the
   * far end is the resolver), or an ET MALWARE rule (already a C2 by the C2 rules).
   */
  public static String toolIn(String alert) {
    if (alert == null || alert.contains(" MALWARE ") || DNS_RULE.matcher(alert).find()) return null;
    if (VENDOR_SERVICE.matcher(alert).find()) return null;
    Matcher m = TOOL.matcher(alert);
    return m.find() ? TOOLS.get(m.group(1).toLowerCase(Locale.ROOT)) : null;
  }

  /** The tool nDPI named a flow as ("TeamViewer", "AnyDesk"…), or null. */
  public static String toolForApp(String ndpiApp) {
    return ndpiApp == null ? null : NDPI_APPS.get(ndpiApp.trim().toLowerCase(Locale.ROOT));
  }

  /**
   * Whether the tool is known as a RAT in its own right (NetSupport), as opposed to an admin tool
   * that is abused now and then (AnyDesk, TeamViewer). Only these are ever escalated to a C2: an IT
   * install of AnyDesk looks the same on the wire as a planted one.
   */
  public static boolean isRat(String tool) {
    return tool != null && RAT_NAMES.containsKey(tool);
  }

  /** "NetSupport RAT" for NetSupport; "AnyDesk (unsanctioned use)" for a tool without one. */
  public static String abuseName(String tool) {
    return RAT_NAMES.getOrDefault(tool, tool + " (unsanctioned use)");
  }
}
