import { expect, test } from '@playwright/test';

/**
 * Visits every standalone route and fails on a broken API call or a console error.
 *
 * This is the test that would have caught #630 directly. The extracted-file download had
 * pointed at `/api/files/...` since #158 while every route is served under `/api/v1`; the
 * existing e2e walkthrough is thorough down one happy path but never touched that control,
 * so the 404 shipped and stayed. A sweep asserts something weaker about each page than a
 * scripted journey does, but it asserts it about *every* page — and a request 404ing is
 * exactly the shape of failure that hides from a journey test.
 *
 * Routes taking a `:fileId` are excluded: they need an uploaded, analysed capture, which
 * `demo.spec.ts` sets up properly. This covers what can stand alone.
 */
const ROUTES = ['/', '/compare', '/monitor'] as const;

/** Requests the app makes to itself. A failure here is a broken contract, not a flaky CDN. */
const API_CALL = /\/api\//;

for (const route of ROUTES) {
  test(`${route} loads without failed API calls or console errors`, async ({ page }) => {
    const consoleErrors: string[] = [];
    const failedRequests: string[] = [];

    page.on('console', message => {
      if (message.type() === 'error') {
        consoleErrors.push(message.text());
      }
    });

    // Response-level, not requestfailed: a 404 is a *successful* HTTP exchange as far as the
    // network layer is concerned, so requestfailed never fires for it. That is precisely how
    // #630 stayed invisible.
    page.on('response', response => {
      const url = response.url();
      if (API_CALL.test(url) && response.status() >= 400) {
        failedRequests.push(`${response.status()} ${url}`);
      }
    });

    await page.goto(route, { waitUntil: 'domcontentloaded' });

    // Not networkidle: the app polls (analysis progress, monitor snapshots), so the network
    // never goes idle and every route times out at 90s. Wait for the shell to prove the SPA
    // mounted, then allow a bounded window for the route's initial calls to land.
    await expect(page.getByText('TracePcap').first()).toBeVisible({ timeout: 30_000 });
    await page.waitForTimeout(3_000);

    expect(failedRequests, `failed API calls on ${route}`).toEqual([]);
    expect(consoleErrors, `console errors on ${route}`).toEqual([]);
  });
}
