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
  void stoppingAnEngineThatNeverStartedIsHarmless(@TempDir Path tmp) {
    // @PreDestroy runs on every shutdown, including ones where no capture was ever analysed.
    configure(true, tmp.resolve("suricata.sock").toString());

    engine.stop();
  }
}
