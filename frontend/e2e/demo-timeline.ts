import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Records which spans of the demo recording are dead time, so the encoder can
 * fast-forward exactly those (see scripts/record-demo.sh).
 *
 * Waiting on an LLM is real — insight generation takes ~20s+ — but nobody wants
 * to watch it. Rather than hide the wait, the GIF races through it: the spinner
 * is visibly on screen, just at 10x. Timestamps beat a hardcoded trim because
 * these waits are model- and machine-dependent.
 */

const here = path.dirname(fileURLToPath(import.meta.url));
export const TIMELINE_FILE = path.resolve(here, '../test-results/demo-timeline.json');

export interface Span {
  /** Seconds from recording start. */
  start: number;
  end: number;
  /** Playback multiplier for this span (10 = 10x faster). */
  speed: number;
  /** Shown in the script's log, so a slow beat is identifiable. */
  label: string;
}

/**
 * How hard to race the waits. A story generation can run 3+ minutes against a
 * local model, which even at 10x is ~19s of spinner — most of the finished GIF.
 * The wait is still shown, just briefly: the point is that the work is real, not
 * that you watch it. Override with DEMO_FF_SPEED to slow it back down.
 */
const SPEED = Number(process.env.DEMO_FF_SPEED ?? 40);

export class Timeline {
  private t0 = Date.now();
  private spans: Span[] = [];

  /** Call when the first page load starts — video recording begins there. */
  start() {
    this.t0 = Date.now();
  }

  private now() {
    return (Date.now() - this.t0) / 1000;
  }

  /**
   * Run `fn`, and mark however long it took as fast-forwarded. Only marks the
   * span if the wait is long enough to be worth cutting — a fast LLM response
   * shouldn't produce a jarring 0.3s speed blip.
   */
  async fastForward<T>(label: string, minSeconds: number, fn: () => Promise<T>): Promise<T> {
    const start = this.now();
    const result = await fn();
    const end = this.now();
    if (end - start >= minSeconds) {
      this.spans.push({ start, end, speed: SPEED, label });
    }
    return result;
  }

  write() {
    fs.mkdirSync(path.dirname(TIMELINE_FILE), { recursive: true });
    fs.writeFileSync(TIMELINE_FILE, JSON.stringify({ spans: this.spans }, null, 2));
  }
}
