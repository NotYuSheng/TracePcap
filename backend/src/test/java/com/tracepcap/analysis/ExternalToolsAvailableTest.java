package com.tracepcap.analysis;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The tools the extraction tests need must actually be present (#701).
 *
 * <p>Those services degrade gracefully by design: a missing binary is not an error, so the
 * subprocess fails to start, the catch fires, the method returns early, and every assertion in
 * {@code DnsQueryLogExtractorTest} still holds. Hiding {@code tshark} from {@code PATH} locally
 * produced <b>13 passed</b>, exactly as with it present — the tests were verifying the
 * degradation path while claiming to verify extraction.
 *
 * <p>That is invisible from a test report, which is why it survived: CI and a developer's machine
 * ran identical counts, 340 tests and 1 skipped in both, and differed only by ~2,100 covered
 * instructions.
 *
 * <p>This fails instead. It is not testing the tools; it is asserting the precondition that makes
 * the other tests mean anything.
 */
class ExternalToolsAvailableTest {

  @ParameterizedTest
  @ValueSource(strings = {"tshark", "editcap", "capinfos"})
  void theToolIsOnThePath(String tool) {
    assertThat(canRun(tool))
        .as(
            "%s is missing. The extraction tests will still pass without it — they will just be "
                + "exercising the graceful-degradation path instead of the parsing they are named "
                + "for (#701). Install it rather than deleting this assertion.",
            tool)
        .isTrue();
  }

  private static boolean canRun(String tool) {
    try {
      Process p = new ProcessBuilder(tool, "--version").redirectErrorStream(true).start();
      if (!p.waitFor(20, TimeUnit.SECONDS)) {
        p.destroyForcibly();
        return false;
      }
      return p.exitValue() == 0;
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      return false;
    } catch (IOException e) {
      return false;
    }
  }
}
