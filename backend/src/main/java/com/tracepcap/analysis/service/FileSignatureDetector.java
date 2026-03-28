package com.tracepcap.analysis.service;

/**
 * Detects file types from the leading bytes of a packet payload (stored as a lowercase hex string).
 *
 * <p>Signatures are checked in declaration order; the first match wins. Sources:
 * https://en.wikipedia.org/wiki/List_of_file_signatures
 */
public final class FileSignatureDetector {

  private FileSignatureDetector() {}

  private record Signature(String hexPrefix, String label) {}

  /**
   * Signatures to match against the start of the payload hex string. Longer/more-specific patterns
   * are listed first so they take priority over shorter ones that share the same prefix.
   * All hex prefixes must be lowercase.
   */
  private static final Signature[] SIGNATURES = {
    // ── Archives ────────────────────────────────────────────────────────────
    new Signature("377abcaf271c",    "7-ZIP"),
    new Signature("526172211a0700",  "RAR"),
    new Signature("526172211a0701",  "RAR5"),
    new Signature("504b0304",        "ZIP"),   // also DOCX / XLSX / ODT / JAR etc.
    new Signature("1f8b",            "GZIP"),
    new Signature("425a68",          "BZIP2"),
    new Signature("fd377a585a00",    "XZ"),
    // ── Executables / binaries ───────────────────────────────────────────────
    new Signature("4d5a",            "EXE/DLL"),  // Windows PE (MZ)
    new Signature("7f454c46",        "ELF"),      // Linux/Unix ELF
    new Signature("cafebabe",        "CLASS"),    // Java class file (also Mach-O fat binary)
    new Signature("feedface",        "MACHO32"),  // Mach-O 32-bit LE
    new Signature("feedfacf",        "MACHO64"),  // Mach-O 64-bit LE
    new Signature("cefaedfe",        "MACHO32"),  // Mach-O 32-bit BE
    new Signature("cffaedfe",        "MACHO64"),  // Mach-O 64-bit BE
    // ── Documents ────────────────────────────────────────────────────────────
    new Signature("25504446",        "PDF"),      // %PDF
    new Signature("d0cf11e0a1b11ae1","DOC/XLS"),  // MS Office legacy (OLE2)
    // ── Images ───────────────────────────────────────────────────────────────
    new Signature("89504e470d0a1a0a","PNG"),
    new Signature("ffd8ff",          "JPEG"),
    new Signature("47494638",        "GIF"),      // GIF87a / GIF89a
    new Signature("424d",            "BMP"),
    new Signature("49492a00",        "TIFF"),     // little-endian
    new Signature("4d4d002a",        "TIFF"),     // big-endian
    new Signature("38425053",        "PSD"),
    new Signature("52494646",        "RIFF"),     // WAV / AVI / WebP
    // ── Media ────────────────────────────────────────────────────────────────
    new Signature("494433",          "MP3"),      // ID3-tagged
    new Signature("fffb",            "MP3"),
    new Signature("fff3",            "MP3"),
    new Signature("fff2",            "MP3"),
    new Signature("4f676753",        "OGG"),
    new Signature("664c6143",        "FLAC"),
    // ── Database / data ──────────────────────────────────────────────────────
    new Signature("53514c69746533",  "SQLITE"),   // SQLite3
    // ── Scripts / text (common transfer indicators) ──────────────────────────
    new Signature("efbbbf",          "UTF8-BOM"),
  };

  /**
   * Returns a short file-type label (e.g. {@code "PDF"}, {@code "EXE/DLL"}) if the start of
   * {@code payloadHex} matches a known signature, or {@code null} if no match is found.
   *
   * @param payloadHex lowercase hex string of the application-layer payload (may be null or empty)
   */
  public static String detect(String payloadHex) {
    if (payloadHex == null || payloadHex.length() < 4) return null;
    for (Signature sig : SIGNATURES) {
      if (payloadHex.startsWith(sig.hexPrefix())) return sig.label();
    }
    return null;
  }
}
