import { test, expect } from '@playwright/test';

test.describe('app smoke', () => {
  test('home/upload page renders', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByText('TracePcap').first()).toBeVisible();
    // Primary nav is present
    await expect(page.getByRole('link', { name: /Analyse/i })).toBeVisible();
    await expect(page.getByRole('link', { name: /Monitor/i })).toBeVisible();
  });
});
