package com.tracepcap.analysis.service;

import jakarta.annotation.PreDestroy;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * A Suricata engine kept warm across analyses (#569).
 *
 * <p>Suricata spends ~45 s building its detection engine from the ~50,000-rule Emerging Threats
 * ruleset and then processes a small capture in ~0.05 s. Run as a fresh subprocess per file, that
 * fixed cost is paid every time: measured at 45.9 s for a 9 KB, 38-packet capture, of which the
 * packet processing was 46 ms. It is the dominant cost of an analysis regardless of capture size,
 * which is why it matters most at scale — the same 45 s for every one of a million files.
 *
 * <p>Suricata's own answer to this is unix-socket mode: one process loads the rules once and
 * accepts captures over a socket. Measured on the same captures, per-file cost drops from 45.9 s to
 * 0.7 s — 66× — with byte-identical alert output.
 *
 * <p><b>Degrades rather than fails.</b> If the socket never comes up, or a submission fails, the
 * caller falls back to the cold subprocess. A warm engine is an optimisation; losing it must not
 * lose threat detection.
 *
 * <p><b>Serialised.</b> Suricata processes queued captures one at a time, and {@code pcap-current}
 * reports a single global "what am I working on", so two concurrent submissions could not tell
 * whose file had finished. The lock makes that explicit; it costs no throughput, because the engine
 * was serial regardless.
 */
@Slf4j
@Component
public class SuricataEngine {

  private static final String SURICATASC = "suricatasc";
  private static final String SURICATA = "suricata";

  @Value("${tracepcap.suricata.warm-engine.enabled:true}")
  private boolean warmEngineEnabled;

  /** Where the command socket lives. Must be writable by the runtime user. */
  @Value("${tracepcap.suricata.warm-engine.socket:/tmp/tracepcap-suricata/suricata.sock}")
  private String socketPath;

  /** Generous: the engine build is tens of seconds and a slow host must not be declared broken. */
  @Value("${tracepcap.suricata.warm-engine.startup-timeout-seconds:180}")
  private int startupTimeoutSeconds;

  /** A single capture should never take this long once the engine is warm. */
  @Value("${tracepcap.suricata.warm-engine.run-timeout-seconds:600}")
  private int runTimeoutSeconds;

  private final ReentrantLock lock = new ReentrantLock();
  private volatile Process daemon;

  /**
   * Starts the engine if it is not already running, and waits for it to accept commands.
   *
   * <p>Called lazily rather than at boot: an application that never analyses a capture should not
   * hold a Suricata process, and a 45 s startup must not delay readiness.
   */
  private boolean ensureStarted() {
    if (!warmEngineEnabled) return false;
    if (isResponsive()) return true;

    try {
      Path socket = Path.of(socketPath);
      Files.createDirectories(socket.getParent());
      Files.deleteIfExists(socket);

      // Socket mode rejects -l, so the log directory has to come from config instead. The
      // packaged default (/var/log/suricata) is root-owned and the runtime user is not root, so
      // without this the engine exits immediately with SC_ERR_LOGDIR_CONFIG.
      Path engineLogDir = socket.getParent().resolve("log");
      Files.createDirectories(engineLogDir);

      log.info("Starting warm Suricata engine on {} (first run builds the ruleset)", socketPath);
      daemon =
          new ProcessBuilder(
                  SURICATA,
                  "--unix-socket=" + socketPath,
                  // Same reason the per-file path sets it: Suricata otherwise starts one worker
                  // per core, each pre-allocating large stream/flow pools. On a 112-core host that
                  // fails thread init ("pool grow failed") and the engine limps — measured 165s
                  // for a capture the per-file path did in 46s, i.e. worse than the bug being
                  // fixed. One packet thread is right for a one-shot offline read either way.
                  "--runmode",
                  "single",
                  "--set",
                  "default-log-dir=" + engineLogDir.toAbsolutePath())
              // Kept, not discarded: a warm engine that fails silently is worse than no warm
              // engine, because the fallback hides it and only the timings show anything is wrong.
              .redirectErrorStream(true)
              .redirectOutput(engineLogDir.resolve("engine.log").toFile())
              .start();

      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(startupTimeoutSeconds);
      while (System.nanoTime() < deadline) {
        if (!daemon.isAlive()) {
          log.warn("Warm Suricata engine exited during startup — falling back to per-file runs");
          return false;
        }
        if (isResponsive()) {
          log.info("Warm Suricata engine ready");
          return true;
        }
        Thread.sleep(1000);
      }
      log.warn("Warm Suricata engine did not become ready in {}s", startupTimeoutSeconds);
      return false;
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      return false;
    } catch (IOException e) {
      log.warn("Could not start the warm Suricata engine: {}", e.getMessage());
      return false;
    }
  }

  /**
   * Processes {@code pcapFile}, writing eve.json into {@code outDir}.
   *
   * @return true if the warm engine handled it; false if the caller should fall back
   */
  public boolean process(File pcapFile, Path outDir) {
    if (!warmEngineEnabled) return false;
    lock.lock();
    try {
      if (!ensureStarted()) return false;

      String submitted =
          runCommand("pcap-file " + pcapFile.getAbsolutePath() + " " + outDir.toAbsolutePath());
      if (submitted == null || !submitted.contains("OK")) {
        log.warn("Warm Suricata engine rejected the capture ({}) — falling back", submitted);
        return false;
      }

      // pcap-current reports the capture being processed, or "None" when the queue has drained.
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(runTimeoutSeconds);
      while (System.nanoTime() < deadline) {
        String current = runCommand("pcap-current");
        if (current == null) {
          log.warn("Lost contact with the warm Suricata engine — falling back");
          return false;
        }
        if (current.contains("None")) return true;
        Thread.sleep(100);
      }
      log.warn("Warm Suricata engine did not finish within {}s — falling back", runTimeoutSeconds);
      return false;
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      return false;
    } finally {
      lock.unlock();
    }
  }

  private boolean isResponsive() {
    String v = runCommand("version");
    return v != null && v.contains("OK");
  }

  /** Returns the raw suricatasc reply, or null if the command could not be run. */
  private String runCommand(String command) {
    try {
      Process p =
          new ProcessBuilder(List.of(SURICATASC, "-c", command, socketPath))
              .redirectErrorStream(true)
              .start();
      String out = new String(p.getInputStream().readAllBytes());
      if (!p.waitFor(30, TimeUnit.SECONDS)) {
        p.destroyForcibly();
        return null;
      }
      return p.exitValue() == 0 ? out : null;
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      return null;
    } catch (IOException e) {
      return null;
    }
  }

  @PreDestroy
  void stop() {
    Process p = daemon;
    if (p != null && p.isAlive()) {
      p.destroy();
      try {
        if (!p.waitFor(10, TimeUnit.SECONDS)) p.destroyForcibly();
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        p.destroyForcibly();
      }
    }
  }
}
