import { test, expect } from '@playwright/test';

test.describe('app smoke', () => {
  test('home/upload page renders', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByText('TracePcap').first()).toBeVisible();
    // Primary nav is present. Anchored at the end: the home page also links to "monitored network".
    await expect(page.getByRole('link', { name: /Analyse$/ })).toBeVisible();
    await expect(page.getByRole('link', { name: /Monitor$/ })).toBeVisible();
  });
});
