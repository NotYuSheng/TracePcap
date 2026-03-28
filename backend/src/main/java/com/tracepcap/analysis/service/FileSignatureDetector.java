package com.tracepcap.analysis.service;

/**
 * Detects file types from the leading bytes of a packet payload (stored as a lowercase hex string).
 *
 * <p>Signatures are checked in declaration order; the first match wins. Sources:
 * https://en.wikipedia.org/wiki/List_of_file_signatures
 */
public final class FileSignatureDetector {

  private FileSignatureDetector() {}

  /**
   * Each entry is {@code {hexPrefix, label}} where {@code hexPrefix} is a lowercase hex string
   * that must appear at offset 0 of the payload. Longer/more-specific patterns are listed first so
   * they take priority over shorter ones that share the same prefix.
   */
  private static final String[][] SIGNATURES = {
    // ── Archives ────────────────────────────────────────────────────────────
    {"377abcaf271c",   "7-ZIP"},
    {"526172211a0700", "RAR"},
    {"526172211a0701", "RAR5"},
    {"504b0304",        "ZIP"},   // also DOCX / XLSX / ODT / JAR etc.
    {"1f8b",           "GZIP"},
    {"425a68",         "BZIP2"},
    {"fd377a585a00",   "XZ"},
    // ── Executables / binaries ───────────────────────────────────────────────
    {"4d5a",           "EXE/DLL"},  // Windows PE  (MZ)
    {"7f454c46",       "ELF"},      // Linux/Unix ELF
    {"cafebabe",       "CLASS"},    // Java class file  (also Mach-O fat binary)
    {"feedface",       "MACHO32"},  // Mach-O 32-bit LE
    {"feedfacf",       "MACHO64"},  // Mach-O 64-bit LE
    {"cefaedfe",       "MACHO32"},  // Mach-O 32-bit BE
    {"cffaedfe",       "MACHO64"},  // Mach-O 64-bit BE
    // ── Documents ────────────────────────────────────────────────────────────
    {"25504446",       "PDF"},      // %PDF
    {"d0cf11e0a1b11ae1","DOC/XLS"}, // MS Office legacy (OLE2)
    // ── Images ───────────────────────────────────────────────────────────────
    {"89504e470d0a1a0a","PNG"},
    {"ffd8ff",         "JPEG"},
    {"47494638",       "GIF"},      // GIF87a / GIF89a
    {"424d",           "BMP"},
    {"49492a00",       "TIFF"},     // little-endian
    {"4d4d002a",       "TIFF"},     // big-endian
    {"38425053",       "PSD"},
    {"52494646",       "RIFF"},     // WAV / AVI / WebP
    // ── Media ────────────────────────────────────────────────────────────────
    {"494433",         "MP3"},      // ID3-tagged
    {"fffb",           "MP3"},
    {"fff3",           "MP3"},
    {"fff2",           "MP3"},
    {"4f676753",       "OGG"},
    {"664c6143",       "FLAC"},
    {"000000",         "MP4"},      // generic MP4 / MOV (ftyp box, first 3 bytes shared)
    // ── Database / data ──────────────────────────────────────────────────────
    {"53514c69746533", "SQLITE"},   // SQLite3
    // ── Scripts / text (common transfer indicators) ──────────────────────────
    {"efbbbf",         "UTF8-BOM"},
  };

  /**
   * Returns a short file-type label (e.g. {@code "PDF"}, {@code "EXE/DLL"}) if the start of
   * {@code payloadHex} matches a known signature, or {@code null} if no match is found.
   *
   * @param payloadHex lowercase hex string of the packet payload (may be null or empty)
   */
  public static String detect(String payloadHex) {
    if (payloadHex == null || payloadHex.length() < 4) return null;
    String lower = payloadHex.toLowerCase();
    for (String[] sig : SIGNATURES) {
      if (lower.startsWith(sig[0])) return sig[1];
    }
    return null;
  }
}
