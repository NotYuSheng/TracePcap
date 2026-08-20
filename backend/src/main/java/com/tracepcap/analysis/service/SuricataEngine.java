package com.tracepcap.analysis.service;

import com.tracepcap.common.stage.DetectionEngineStatus;
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
public class SuricataEngine implements DetectionEngineStatus {

  private static final String SURICATASC = "suricatasc";
  private static final String SURICATA = "suricata";
  private static final String EVE_JSON = "eve.json";

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

  /**
   * How long a caller waits for the engine before giving up and using the per-file path.
   *
   * <p>Deliberately generous. Falling back is not cheap — it is a 45 s cold Suricata — so waiting
   * for the warm engine is almost always the better trade. A short wait was measurably worse: with
   * eight captures submitted together, every caller but one timed out of the lock and started its
   * own cold Suricata, and the resulting contention pushed a single Extract stage to 430 s. The
   * bound exists to stop an unbounded hang, not to prefer the slow path.
   */
  @Value("${tracepcap.suricata.warm-engine.lock-wait-seconds:900}")
  private int lockWaitSeconds;

  /** A socket command is a single short exchange; anything longer means the engine is wedged. */
  @Value("${tracepcap.suricata.warm-engine.command-timeout-seconds:30}")
  private int commandTimeoutSeconds;

  private final ReentrantLock lock = new ReentrantLock();
  private volatile Process daemon;

  /**
   * Whether the engine has finished building its ruleset.
   *
   * <p>A plain flag rather than a probe: callers ask this to size a progress bar, and shelling out
   * to suricatasc to answer would cost more than the question is worth.
   */
  private volatile boolean warm;

  /**
   * Whether the next capture can skip the ~45 s detection-engine build (#569).
   *
   * <p>Progress estimation needs this because it is the difference between one stage taking 0.3 s
   * and taking 45 s, and no static weighting can describe both (#758).
   */
  @Override
  public boolean isWarm() {
    return warm && daemon != null && daemon.isAlive();
  }

  /** Where a warm run writes, kept apart from the caller's fallback output. */
  public static Path warmDir(Path outDir) {
    return outDir.resolve("warm");
  }

  private void discardDaemon() {
    warm = false;
    Process p = daemon;
    daemon = null;
    if (p != null && p.isAlive()) p.destroyForcibly();
  }

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
      // A daemon can be alive but unresponsive — wedged, or its socket gone. Starting a
      // replacement without stopping it first would orphan a process holding a built rule engine
      // (hundreds of MB) that nothing can reach afterwards. Same defect the startup-timeout path
      // had; this is the restart path.
      discardDaemon();

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
          discardDaemon();
          return false;
        }
        if (isResponsive()) {
          log.info("Warm Suricata engine ready");
          warm = true;
          return true;
        }
        Thread.sleep(1000);
      }
      log.warn("Warm Suricata engine did not become ready in {}s", startupTimeoutSeconds);
      // Alive but unresponsive: without this the next attempt starts a second daemon and this
      // one becomes unreachable, so stop() could never terminate it.
      discardDaemon();
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
    // Bounded: while the engine builds its ruleset (~45s) other analyses should fall back to the
    // per-file path rather than queue behind it.
    try {
      if (!lock.tryLock(lockWaitSeconds, TimeUnit.SECONDS)) return false;
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      return false;
    }
    try {
      if (!ensureStarted()) return false;

      // Its own directory. If a warm run is abandoned on timeout it may still be writing, and the
      // caller's fallback starts a cold Suricata immediately — pointed at the same directory,
      // two processes would append to one eve.json and produce mixed or partial alerts.
      Path warmDir = warmDir(outDir);
      try {
        Files.createDirectories(warmDir);
      } catch (IOException e) {
        return false;
      }

      String submitted =
          runCommand("pcap-file " + pcapFile.getAbsolutePath() + " " + warmDir.toAbsolutePath());
      if (submitted == null || !submitted.contains("OK")) {
        log.warn("Warm Suricata engine rejected the capture ({}) — falling back", submitted);
        return false;
      }

      // pcap-current reports the capture being processed, or "None" when the queue has drained —
      // including in the window after the submission is accepted but before the engine dequeues
      // it. Waiting for eve.json as well distinguishes "not started yet" from "finished".
      Path eve = warmDir.resolve(EVE_JSON);
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(runTimeoutSeconds);
      while (System.nanoTime() < deadline) {
        String current = runCommand("pcap-current");
        if (current == null) {
          log.warn("Lost contact with the warm Suricata engine — falling back");
          discardDaemon();
          return false;
        }
        if (current.contains("None") && Files.exists(eve)) return true;
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
      // waitFor first: readAllBytes blocks until EOF, so a stalled socket command would hold the
      // lock indefinitely and the caller could never fall back. suricatasc replies with a single
      // short JSON line, well inside the pipe buffer, so nothing is lost by draining afterwards.
      if (!p.waitFor(commandTimeoutSeconds, TimeUnit.SECONDS)) {
        p.destroyForcibly();
        return null;
      }
      String out = new String(p.getInputStream().readAllBytes());
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
