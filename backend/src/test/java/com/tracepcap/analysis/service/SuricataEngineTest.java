package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * The warm engine is an optimisation over a threat detector (#569). What matters most in tests is
 * not that it is fast, but that every way it can fail hands the caller back to the per-file path
 * rather than quietly returning no alerts.
 */
class SuricataEngineTest {

  private final SuricataEngine engine = new SuricataEngine();

  private void configure(boolean enabled, String socket) {
    ReflectionTestUtils.setField(engine, "warmEngineEnabled", enabled);
    ReflectionTestUtils.setField(engine, "socketPath", socket);
    ReflectionTestUtils.setField(engine, "startupTimeoutSeconds", 1);
    ReflectionTestUtils.setField(engine, "runTimeoutSeconds", 1);
    ReflectionTestUtils.setField(engine, "lockWaitSeconds", 1);
    ReflectionTestUtils.setField(engine, "commandTimeoutSeconds", 5);
  }

  @Test
  void whenDisabledItDeclinesWithoutTouchingTheFilesystem(@TempDir Path tmp) {
    // The kill-switch has to work without side effects: an operator turning this off should not
    // find a socket directory appearing anyway.
    Path socket = tmp.resolve("nested/deeper/suricata.sock");
    configure(false, socket.toString());

    assertThat(engine.process(new File("irrelevant.pcap"), tmp)).isFalse();
    assertThat(socket.getParent()).doesNotExist();
  }

  @Test
  void whenTheEngineCannotStartItDeclinesRatherThanThrowing(@TempDir Path tmp) {
    // No suricata binary on this path, or a socket that never appears: the caller must get a
    // plain "no" so it can fall back. An exception here would fail the whole analysis for the
    // sake of an optimisation.
    configure(true, tmp.resolve("suricata.sock").toString());

    assertThat(engine.process(new File("irrelevant.pcap"), tmp)).isFalse();
  }

  @Test
  void decliningIsRepeatableRatherThanLeavingTheEngineWedged(@TempDir Path tmp) {
    // Analysis is per-file and long-running; a first failure must not poison every later attempt
    // with a half-initialised process.
    configure(true, tmp.resolve("suricata.sock").toString());

    assertThat(engine.process(new File("a.pcap"), tmp)).isFalse();
    assertThat(engine.process(new File("b.pcap"), tmp)).isFalse();
  }

  @Test
  void warmOutputIsKeptApartFromTheCallersFallbackDirectory(@TempDir Path tmp) {
    // A warm run abandoned on timeout may still be writing while the caller starts the cold
    // subprocess. Pointed at one directory, two Suricatas would append to the same eve.json and
    // produce mixed or partial alerts — so the paths must not be the same.
    assertThat(SuricataEngine.warmDir(tmp)).isNotEqualTo(tmp);
    assertThat(SuricataEngine.warmDir(tmp).getParent()).isEqualTo(tmp);
  }

  @Test
  void aSecondCallerDoesNotQueueBehindAStartingEngine(@TempDir Path tmp) throws Exception {
    // Bounded, not blocking: a caller must eventually give up rather than hang forever. The
    // bound is generous in production (falling back costs a 45s cold run), so this pins the
    // property that the wait terminates, with the timeout configured low.
    configure(true, tmp.resolve("suricata.sock").toString());

    long start = System.nanoTime();
    Thread other = new Thread(() -> engine.process(new File("a.pcap"), tmp));
    other.start();
    engine.process(new File("b.pcap"), tmp);
    other.join();

    long elapsedSeconds = (System.nanoTime() - start) / 1_000_000_000L;
    assertThat(elapsedSeconds).isLessThan(20);
  }

  @Test
  void aRestartDoesNotLeaveTheOldEngineRunning(@TempDir Path tmp) throws Exception {
    // A daemon can be alive but unresponsive. Replacing it without stopping it would orphan a
    // process holding a built rule engine that nothing can reach afterwards.
    configure(true, tmp.resolve("suricata.sock").toString());
    ReflectionTestUtils.setField(engine, "daemon", new ProcessBuilder("sleep", "300").start());
    Process orphan = (Process) ReflectionTestUtils.getField(engine, "daemon");

    engine.process(new File("a.pcap"), tmp);

    assertThat(orphan.isAlive()).isFalse();
  }

  @Test
  void stoppingAnEngineThatNeverStartedIsHarmless(@TempDir Path tmp) {
    // @PreDestroy runs on every shutdown, including ones where no capture was ever analysed.
    configure(true, tmp.resolve("suricata.sock").toString());

    engine.stop();
  }
}
