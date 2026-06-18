import { test, expect } from '@playwright/test';
import { uploadAndProcessFixture, LLM_UNREACHABLE_502 } from './helpers';

/**
 * Regression guard for #384: when the LLM is unreachable (502), the UI must show
 * a visible error alert — not a blank/empty container. The blank screen was
 * caused by React 19 dropping SGDS Alert's `defaultProps` so the Alert rendered
 * `null`. These tests force the 502 via route interception and assert the alert
 * is actually visible with its message.
 */

let fileId: string;

test.beforeAll(async ({ request }) => {
  fileId = await uploadAndProcessFixture(request);
});

test('Story tab shows an error alert when story generation returns 502', async ({ page }) => {
  // Force the "no existing story" state so the Generate Story button is shown,
  // regardless of whether this file already has a story persisted.
  await page.route('**/api/story/file/**', route =>
    route.fulfill({ status: 204, body: '' })
  );
  await page.route('**/api/story/generate/**', route =>
    route.fulfill({
      status: 502,
      contentType: 'application/json',
      body: JSON.stringify(LLM_UNREACHABLE_502),
    })
  );

  await page.goto(`/analysis/${fileId}/story`);
  await page.getByRole('button', { name: /Generate Story/i }).click();

  const alert = page.locator('.error-message-container .alert');
  await expect(alert).toBeVisible();
  await expect(alert).toContainText(/LLM server is not responding/i);
  await expect(page.getByRole('button', { name: /Retry/i })).toBeVisible();
});

test('Filter Generator shows an error alert when filter generation returns 502', async ({ page }) => {
  await page.route('**/api/filter/generate/**', route =>
    route.fulfill({
      status: 502,
      contentType: 'application/json',
      body: JSON.stringify(LLM_UNREACHABLE_502),
    })
  );

  await page.goto(`/analysis/${fileId}/filter-generator`);
  await page.locator('textarea').first().fill('show me all HTTP traffic');
  await page.getByRole('button', { name: /Generate Filter/i }).click();

  const alert = page.locator('.alert-danger');
  await expect(alert).toBeVisible();
  await expect(alert).toContainText(/LLM server is not responding/i);
});
