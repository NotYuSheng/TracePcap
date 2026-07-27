import { defineConfig, devices } from '@playwright/test';

/**
 * E2E smoke tests run against a running TracePcap stack (nginx on :8888).
 * Bring the stack up first: `docker compose up -d --build`.
 * Run: `npm run test:e2e` (from frontend/).
 */
// 16:9 at 2x the README's ~640px render width, so the GIF downscale stays sharp.
const DEMO_SIZE = { width: 1280, height: 720 };

// The demo recording is opt-in: `npm run demo:record` sets DEMO=1. Registering
// the project only then keeps a plain `playwright test` from paying its ~40s of
// deliberate pauses (Playwright runs every project by default; --project alone
// can't express "exclude from the default run").
const RECORD_DEMO = process.env.DEMO === '1';

export default defineConfig({
  testDir: './e2e',
  timeout: 90_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',
  use: {
    baseURL: process.env.E2E_BASE_URL || 'http://localhost:8888',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      testIgnore: /demo\.spec\.ts/,
      use: {
        ...devices['Desktop Chrome'],
        launchOptions: { args: ['--no-sandbox'] },
      },
    },
    // README demo recording — see RECORD_DEMO above.
    ...(RECORD_DEMO
      ? [
          {
            name: 'demo' as const,
            testMatch: /demo\.spec\.ts/,
            // The walkthrough's deliberate pauses alone run several minutes, and
            // it also waits out real work on camera: a Suricata-enabled analysis
            // of the uploaded capture, then story and filter generation against a
            // local LLM. Generous rather than tuned — this bounds a hang, it is
            // not a performance assertion, and a recording that dies at minute
            // eight wastes everything before it.
            timeout: 20 * 60_000,
            use: {
              ...devices['Desktop Chrome'],
              launchOptions: { args: ['--no-sandbox'] },
              viewport: DEMO_SIZE,
              video: { mode: 'on' as const, size: DEMO_SIZE },
            },
          },
        ]
      : []),
  ],
});
