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
  await page.getByRole('button', { name: /Write the story/i }).click();

  const alert = page.locator('.error-message-container .alert');
  await expect(alert).toBeVisible();
  await expect(alert).toContainText(/LLM server is not responding/i);
  await expect(page.getByRole('button', { name: /Retry/i })).toBeVisible();
});

test('Story chat shows an actionable alert when the LLM server is unreachable', async ({ page }) => {
  // The chat answers in a background turn; a turn that fails on an unreachable LLM must say so,
  // not leave a spinner (#1161, which also folded the Filter Generator into the chat).
  await page.route('**/api/v1/files/*/chat-turns', route =>
    route.fulfill({
      status: 201,
      contentType: 'application/json',
      body: JSON.stringify({
        id: '00000000-0000-0000-0000-000000000001',
        status: 'FAILED',
        steps: [],
        answer: null,
        followUpQuestions: [],
        filters: [],
        toolsOffered: false,
        error: 'Failed to reach the LLM service',
        errorCode: 'LLM_UNREACHABLE',
        elapsedMs: 10,
      }),
    })
  );

  await page.goto(`/analysis/${fileId}/story`);
  const box = page.getByRole('textbox', { name: 'Ask a question about this capture' });
  await box.fill('A filter for the HTTP traffic');
  await box.press('Enter');

  const alert = page.locator('.story-chat-panel .alert-danger');
  await expect(alert).toBeVisible();
  await expect(alert).toContainText(/LLM server is not responding/i);
});

test('Report download shows an actionable alert when the diagram exceeds the JSON string cap', async ({ page }) => {
  // Regression guard for #792/the GlobalExceptionHandler PAYLOAD_STRING_TOO_LARGE branch: the
  // report POST uses responseType: 'blob' (it's a PDF on success), so an error body comes back as
  // a Blob, not a parsed object — the frontend has to read it out explicitly. Force that exact
  // response via route interception rather than generating an actually-oversized diagram.
  await page.route('**/api/v1/files/*/report', route =>
    route.fulfill({
      status: 413,
      contentType: 'application/json',
      body: JSON.stringify({
        status: 413,
        error: 'Payload Too Large',
        message:
          "Request field is 63 MB, over this deployment's current 51 MB limit "
          + '(derived from APP_MEMORY_MB). Raise APP_MEMORY_MB to at least 2048 in '
          + "the backend's environment and restart it.",
        errorCode: 'PAYLOAD_STRING_TOO_LARGE',
        attemptedSizeMb: 63,
        recommendedAppMemoryMb: 2048,
      }),
    })
  );

  // Download report lives in the Capture tab.
  await page.goto(`/analysis/${fileId}/file`);
  await page.getByRole('button', { name: /Download Report/i }).click();
  // The drawer: leave the map out (it isn't what's under test), then build.
  const drawer = page.getByRole('dialog', { name: 'Download report' });
  await drawer.getByRole('checkbox', { name: 'Network map' }).uncheck();
  await drawer.getByRole('button', { name: /Download PDF/ }).click();

  const alert = drawer.locator('.alert-danger');
  await expect(alert).toBeVisible();
  await expect(alert).toContainText(/too large for this deployment/i);
  await expect(alert).toContainText('63 MB');
  await expect(alert).toContainText('APP_MEMORY_MB');
  await expect(alert).toContainText('2048');
});
