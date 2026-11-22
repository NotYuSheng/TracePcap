package com.tracepcap.analysis.service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Which Suricata ruleset is in use, how old it is, and an operator-supplied replacement (#600).
 *
 * <p><b>Built in.</b> The image bakes the Emerging Threats Open ruleset in at build time, with the
 * build date in {@code /opt/suricata-ruleset-version}. That keeps detection offline, but the rules
 * then age with the image.
 *
 * <p><b>Imported.</b> An operator can drop a newer bundle into {@link #importDir} (a mounted
 * folder): ET's {@code emerging.rules.tar.gz}, or one or more {@code .rules} files. It's checked
 * every minute; a new or changed bundle is unpacked into a writable folder and test-loaded with
 * {@code suricata -T} before it's used. Only a bundle that loads replaces the built-in rules; a
 * broken one is reported and the built-in rules stay, so Suricata is never left with none.
 * Nothing is ever downloaded.
 *
 * <p>Validation loads the whole ruleset (about a minute and hundreds of MB), so it runs with the
 * warm engine stopped, inside the engine's lock ({@link SuricataEngine#withEngineStopped}).
 */
@Slf4j
@Component
public class SuricataRuleset {

  static final Path BAKED_RULES = Path.of("/etc/suricata/rules/suricata.rules");
  static final Path BAKED_DATE = Path.of("/opt/suricata-ruleset-version");
  static final Path ENGINE_VERSION = Path.of("/opt/suricata-version");
  static final Path BAKED_CLASSIFICATION = Path.of("/etc/suricata/classification.config");
  static final Path BAKED_REFERENCE = Path.of("/etc/suricata/reference.config");

  /** A rule line: an action keyword at the start (commented-out rules don't count). */
  private static final Pattern RULE_LINE =
      Pattern.compile("^\\s*(alert|drop|pass|reject|rejectsrc|rejectdst|rejectboth)\\s");

  /** ET's per-rule metadata date, e.g. {@code updated_at 2026_11_20}. */
  private static final Pattern UPDATED_AT = Pattern.compile("updated_at (\\d{4})_(\\d{2})_(\\d{2})");

  @Value("${tracepcap.suricata.rules-import-dir:/var/lib/tracepcap/suricata-rules}")
  private String importDir;

  /** Where an imported bundle is unpacked and assembled; must be writable by the runtime user. */
  @Value("${tracepcap.suricata.rules-work-dir:/tmp/tracepcap-suricata/imported}")
  private String workDir;

  @Value("${tracepcap.suricata.ruleset-stale-days:30}")
  private int staleDays;

  @Value("${tracepcap.suricata.validate-timeout-seconds:300}")
  private int validateTimeoutSeconds;

  private final SuricataEngine engine;

  /** The ruleset in use. Starts as the built-in one; replaced only by a bundle that loaded. */
  private volatile Active active;

  /** What the import folder held when last looked at, so an unchanged folder isn't re-validated. */
  private volatile String lastSeenImport = "";

  /** Why the last imported bundle wasn't used, or null. */
  private volatile String importError;

  public SuricataRuleset(SuricataEngine engine) {
    this.engine = engine;
    this.engine.setRuleset(this);
  }

  /** The ruleset in use: where its rules are, how it's dated, and how many rules it has. */
  public record Active(
      String source, Path rulesFile, Path classification, Path reference, LocalDate date, int ruleCount) {
    boolean imported() {
      return "imported".equals(source);
    }
  }

  /** What the API reports (GET /system/suricata). */
  public record Status(
      String engineVersion,
      String source,
      LocalDate rulesetDate,
      Long ageDays,
      boolean stale,
      int staleAfterDays,
      int ruleCount,
      String importDir,
      String importError) {}

  /** The ruleset in use. */
  public Active active() {
    Active a = active;
    if (a == null) {
      synchronized (this) {
        if (active == null) active = baked();
        a = active;
      }
    }
    return a;
  }

  /**
   * Extra Suricata arguments that select the active ruleset: none for the built-in one (the
   * packaged suricata.yaml already points at it), {@code -S} plus its configs for an imported one.
   */
  public List<String> suricataArgs() {
    Active a = active();
    if (!a.imported()) return List.of();
    List<String> args = new ArrayList<>(List.of("-S", a.rulesFile().toString()));
    if (a.classification() != null) {
      args.add("--set");
      args.add("classification-file=" + a.classification());
    }
    if (a.reference() != null) {
      args.add("--set");
      args.add("reference-config-file=" + a.reference());
    }
    return args;
  }

  /** Status for the API and the UI. */
  public Status status() {
    Active a = active();
    Long age = a.date() == null ? null : ChronoUnit.DAYS.between(a.date(), LocalDate.now(ZoneOffset.UTC));
    return new Status(
        readFirstLine(ENGINE_VERSION),
        a.source(),
        a.date(),
        age,
        age != null && age > staleDays,
        staleDays,
        a.ruleCount(),
        importDir,
        importError);
  }

  /**
   * Looks at the import folder every minute. A new or changed bundle is validated and, if it
   * loads, made active; a removed one reverts to the built-in rules.
   */
  @Scheduled(initialDelayString = "PT20S", fixedDelayString = "PT60S")
  public void checkImports() {
    Path dir = Path.of(importDir);
    String fingerprint = fingerprint(dir);
    if (fingerprint.equals(lastSeenImport)) return;
    lastSeenImport = fingerprint;

    if (fingerprint.isEmpty()) {
      if (active().imported()) {
        log.info("Suricata import folder {} is empty: back to the built-in ruleset", dir);
        engine.withEngineStopped(() -> active = baked());
      }
      importError = null;
      return;
    }
    log.info("New Suricata ruleset bundle in {}: validating before use", dir);
    engine.withEngineStopped(() -> importFrom(dir));
  }

  /** Unpacks, assembles and test-loads a bundle; makes it active only if Suricata loads it. */
  void importFrom(Path dir) {
    try {
      Path work = Path.of(workDir);
      Path staging = work.resolveSibling(work.getFileName() + ".staging");
      deleteRecursively(staging);
      Files.createDirectories(staging);
      LocalDate date = assemble(dir, staging);
      Path rules = staging.resolve("suricata.rules");
      int count = countRules(rules);
      if (count == 0) {
        reject("the bundle has no rules");
        return;
      }
      Path classification = existingOr(staging.resolve("classification.config"), BAKED_CLASSIFICATION);
      Path reference = existingOr(staging.resolve("reference.config"), BAKED_REFERENCE);
      String failure = testLoad(rules, classification, reference, staging);
      if (failure != null) {
        reject(failure);
        return;
      }
      // Loaded: swap the staging folder into place, then point the configs at their final paths.
      deleteRecursively(work);
      Files.move(staging, work, StandardCopyOption.ATOMIC_MOVE);
      active =
          new Active(
              "imported",
              work.resolve("suricata.rules"),
              classification.startsWith(staging) ? work.resolve(classification.getFileName()) : classification,
              reference.startsWith(staging) ? work.resolve(reference.getFileName()) : reference,
              date,
              count);
      importError = null;
      log.info("Imported Suricata ruleset is active: {} rules, dated {}", count, date);
    } catch (IOException e) {
      reject("couldn't read the bundle: " + e.getMessage());
    }
  }

  private void reject(String why) {
    importError = why;
    log.warn("Imported Suricata ruleset not used ({}); keeping the {} ruleset", why, active().source());
  }

  /**
   * Builds {@code suricata.rules} (and ET's configs, when present) in {@code out} from the bundle.
   * Returns the ruleset's date: a tarball's newest entry (ET's publication time), else the newest
   * rule's {@code updated_at}, else the newest file's modification date.
   */
  static LocalDate assemble(Path dir, Path out) throws IOException {
    List<Path> tarballs = list(dir, p -> p.toString().endsWith(".tar.gz") || p.toString().endsWith(".tgz"));
    Path rulesOut = out.resolve("suricata.rules");
    if (!tarballs.isEmpty()) {
      Path newest = tarballs.stream().max(Comparator.comparing(SuricataRuleset::mtime)).orElseThrow();
      Path unpack = out.resolve("unpacked");
      Files.createDirectories(unpack);
      run(List.of("tar", "-xzf", newest.toString(), "-C", unpack.toString()), 120);
      List<Path> ruleFiles;
      try (Stream<Path> s = Files.walk(unpack)) {
        ruleFiles = s.filter(p -> p.toString().endsWith(".rules")).sorted().toList();
      }
      concat(ruleFiles, rulesOut);
      for (String config : List.of("classification.config", "reference.config")) {
        try (Stream<Path> s = Files.walk(unpack)) {
          s.filter(p -> p.getFileName().toString().equals(config))
              .findFirst()
              .ifPresent(p -> copy(p, out.resolve(config)));
        }
      }
      LocalDate newestEntry = newestMtime(unpack);
      deleteRecursively(unpack);
      return newestEntry;
    }
    List<Path> ruleFiles = list(dir, p -> p.toString().endsWith(".rules"));
    concat(ruleFiles, rulesOut);
    for (String config : List.of("classification.config", "reference.config")) {
      Path p = dir.resolve(config);
      if (Files.isRegularFile(p)) copy(p, out.resolve(config));
    }
    LocalDate updated = newestUpdatedAt(rulesOut);
    return updated != null ? updated : newestMtime(dir);
  }

  /** Runs {@code suricata -T} on the ruleset; returns why it failed, or null if it loaded. */
  private String testLoad(Path rules, Path classification, Path reference, Path workDir) {
    try {
      Path log = workDir.resolve("validate-log");
      Files.createDirectories(log);
      List<String> cmd =
          new ArrayList<>(
              List.of(
                  "suricata", "-T", "-S", rules.toString(), "--runmode", "single",
                  "--set", "default-log-dir=" + log,
                  "--set", "unix-command.enabled=no"));
      if (classification != null) cmd.addAll(List.of("--set", "classification-file=" + classification));
      if (reference != null) cmd.addAll(List.of("--set", "reference-config-file=" + reference));
      String output = run(cmd, validateTimeoutSeconds);
      return output.contains("successfully loaded") ? null : "Suricata couldn't load it";
    } catch (IOException e) {
      return "Suricata couldn't load it (" + firstLine(e.getMessage()) + ")";
    }
  }

  private Active baked() {
    LocalDate date = null;
    String d = readFirstLine(BAKED_DATE);
    if (d != null) {
      try {
        date = LocalDate.parse(d.trim());
      } catch (RuntimeException ignored) {
        // an unreadable date is reported as unknown, not fatal
      }
    }
    return new Active("built-in", BAKED_RULES, null, null, date, countRules(BAKED_RULES));
  }

  /** What's in the import folder (names, sizes, times); empty when there's no usable bundle. */
  static String fingerprint(Path dir) {
    if (!Files.isDirectory(dir)) return "";
    List<Path> files =
        list(dir, p -> p.toString().endsWith(".rules") || p.toString().endsWith(".tar.gz") || p.toString().endsWith(".tgz"));
    StringBuilder sb = new StringBuilder();
    for (Path p : files) {
      try {
        sb.append(p.getFileName()).append(':').append(Files.size(p)).append(':').append(mtime(p)).append(';');
      } catch (IOException ignored) {
        // a file that vanished mid-scan shows up on the next pass
      }
    }
    return sb.toString();
  }

  static int countRules(Path rules) {
    if (!Files.isReadable(rules)) return 0;
    int n = 0;
    try (BufferedReader r = Files.newBufferedReader(rules, StandardCharsets.UTF_8)) {
      String line;
      while ((line = r.readLine()) != null) if (RULE_LINE.matcher(line).find()) n++;
    } catch (IOException e) {
      return 0;
    }
    return n;
  }

  static LocalDate newestUpdatedAt(Path rules) {
    LocalDate newest = null;
    try (BufferedReader r = Files.newBufferedReader(rules, StandardCharsets.UTF_8)) {
      String line;
      while ((line = r.readLine()) != null) {
        if (!RULE_LINE.matcher(line).find()) continue;
        Matcher m = UPDATED_AT.matcher(line);
        if (!m.find()) continue;
        try {
          LocalDate d = LocalDate.of(Integer.parseInt(m.group(1)), Integer.parseInt(m.group(2)), Integer.parseInt(m.group(3)));
          if (newest == null || d.isAfter(newest)) newest = d;
        } catch (RuntimeException ignored) {
          // a malformed date on one rule doesn't date the ruleset
        }
      }
    } catch (IOException e) {
      return null;
    }
    return newest;
  }

  private static List<Path> list(Path dir, java.util.function.Predicate<Path> keep) {
    try (Stream<Path> s = Files.list(dir)) {
      return s.filter(Files::isRegularFile).filter(keep).sorted().toList();
    } catch (IOException e) {
      return List.of();
    }
  }

  private static void concat(List<Path> files, Path out) throws IOException {
    try (var w = Files.newOutputStream(out)) {
      for (Path f : files) {
        try (InputStream in = Files.newInputStream(f)) {
          in.transferTo(w);
        }
        w.write('\n');
      }
    }
  }

  private static void copy(Path from, Path to) {
    try {
      Files.copy(from, to, StandardCopyOption.REPLACE_EXISTING);
    } catch (IOException e) {
      log.debug("Couldn't copy {}: {}", from, e.getMessage());
    }
  }

  private static Path existingOr(Path preferred, Path fallback) {
    if (Files.isRegularFile(preferred)) return preferred;
    return Files.isRegularFile(fallback) ? fallback : null;
  }

  private static long mtime(Path p) {
    try {
      return Files.getLastModifiedTime(p).toMillis();
    } catch (IOException e) {
      return 0;
    }
  }

  private static LocalDate newestMtime(Path dir) {
    try (Stream<Path> s = Files.walk(dir)) {
      long newest = s.filter(Files::isRegularFile).mapToLong(SuricataRuleset::mtime).max().orElse(0);
      return newest == 0 ? null : Instant.ofEpochMilli(newest).atZone(ZoneOffset.UTC).toLocalDate();
    } catch (IOException e) {
      return null;
    }
  }

  /** Runs a command, returning its combined output; throws if it fails or runs too long. */
  private static String run(List<String> cmd, int timeoutSeconds) throws IOException {
    Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
    StringBuilder out = new StringBuilder();
    Thread reader =
        new Thread(
            () -> {
              try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = r.readLine()) != null) out.append(line).append('\n');
              } catch (IOException ignored) {
                // the process ended
              }
            });
    reader.setDaemon(true);
    reader.start();
    try {
      if (!p.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
        p.destroyForcibly();
        throw new IOException(cmd.get(0) + " timed out after " + timeoutSeconds + "s");
      }
      reader.join(5000);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      p.destroyForcibly();
      throw new IOException("interrupted");
    }
    if (p.exitValue() != 0) throw new IOException(cmd.get(0) + " exited " + p.exitValue() + ": " + lastLines(out.toString()));
    return out.toString();
  }

  private static String lastLines(String s) {
    String[] lines = s.strip().split("\n");
    return lines.length == 0 ? "" : lines[lines.length - 1];
  }

  private static String firstLine(String s) {
    return s == null ? "" : s.split("\n")[0];
  }

  private static String readFirstLine(Path p) {
    try {
      List<String> lines = Files.readAllLines(p);
      return lines.isEmpty() ? null : lines.get(0).trim();
    } catch (IOException e) {
      return null;
    }
  }

  private static void deleteRecursively(Path dir) {
    if (!Files.exists(dir)) return;
    try (Stream<Path> paths = Files.walk(dir)) {
      paths.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
    } catch (IOException e) {
      log.debug("Couldn't delete {}: {}", dir, e.getMessage());
    }
  }
}
