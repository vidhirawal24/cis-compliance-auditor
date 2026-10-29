import { test, expect } from '@playwright/test';
import path from 'node:path';

for (const scenario of ['disabled', 'missing', 'malformed'] as const) {
  test(`built production app fails closed for ${scenario} configuration`, async ({ page }) => {
    if (scenario === 'missing') await page.route('**/baselineguard-config.json', route => route.fulfill({ status: 503, body: 'Unavailable' }));
    if (scenario === 'malformed') await page.route('**/baselineguard-config.json', route => route.fulfill({ json: { mode: 'typo' } }));
    await page.goto('/orgs');
    await expect(page.getByRole('heading', { name: 'Sign In to Workspace' })).toBeVisible();
    await expect(page.getByText('Acme Financial SecOps (DEMO)', { exact: true })).toHaveCount(0);
    await page.getByRole('button', { name: 'Quick Sign-In (DEMO Mode)' }).click();
    await expect(page.getByText('DEMO sign-in is disabled for this environment.')).toBeVisible();
    await expect(page.getByText('JBSWY3DPEHPK3PXP', { exact: true })).toHaveCount(0);
    if (scenario === 'disabled') await page.screenshot({ path: path.resolve('../../docs/frontend/screenshots/phase10-production-disabled.png'), fullPage: true });
  });
}
