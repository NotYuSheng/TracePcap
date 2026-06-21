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
  // Story endpoints collapsed onto /stories: GET ?fileId= (lookup) and POST (generate).
  // One route, branched by method — force "no existing story" (204) so the Generate
  // button shows, and a 502 on generate.
  await page.route('**/api/v1/stories**', route => {
    if (route.request().method() === 'POST') {
      return route.fulfill({
        status: 502,
        contentType: 'application/json',
        body: JSON.stringify(LLM_UNREACHABLE_502),
      });
    }
    return route.fulfill({ status: 204, body: '' });
  });

  await page.goto(`/analysis/${fileId}/story`);
  await page.getByRole('button', { name: /Generate Story/i }).click();

  const alert = page.locator('.error-message-container .alert');
  await expect(alert).toBeVisible();
  await expect(alert).toContainText(/LLM server is not responding/i);
  await expect(page.getByRole('button', { name: /Retry/i })).toBeVisible();
});

test('Filter Generator shows an error alert when filter generation returns 502', async ({ page }) => {
  await page.route('**/api/v1/filter/*/generate', route =>
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
