import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import path from 'node:path';

const org = 'e9c80d50-1011-42e1-88f2-aa11bb22cc01';
test('DEMO navigation, plan selection and contract-violation blocking', async ({ page }) => {
  await page.goto(`/orgs/${org}/planner`);
  await page.getByRole('button', { name: 'Select plan: Restrictive ACL hypothesis' }).click();
  await page.getByRole('button', { name: /Proceed to What-If/ }).click();
  await page.getByRole('button', { name: 'Load DEMO comparison' }).click();
  await expect(page.getByText('VIOLATES_CONTRACT', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: /Proceed to Approval/ })).toBeDisabled();
  await page.goto(`/orgs/${org}/approvals`);
  await expect(page.getByText(/Approval blocked:/)).toBeVisible();
  await expect(page.getByRole('button', { name: /Approve plan/ })).toBeDisabled();
});

test('asset search, role-denied navigation and report limits', async ({ page }) => {
  await page.goto(`/orgs/${org}/assets`);
  await expect(page.getByText('Asset Inventory (E01)', { exact: true })).toBeVisible();
  await page.goto(`/orgs/${org}/reports`);
  await expect(page.getByRole('heading', { name: 'PDF exports' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Retrieve PDF' })).toBeDisabled();
  await expect(page.getByRole('button', { name: /Generate new report/ })).toBeDisabled();
  await page.getByLabel('Switch Active Role').selectOption('VIEWER');
  await page.goto(`/orgs/${org}/admin/users`);
  // Reload resets the explicit DEMO persona; use an in-app role transition instead.
  await page.getByLabel('Switch Active Role').selectOption('VIEWER');
  await expect(page.getByRole('heading', { name: 'Access Denied' })).toBeVisible();
});

for (const [route, heading] of [
  ['overview', 'Security Posture & Compliance Overview'],
  ['reports', 'Compliance Reports & Drift Timeline'],
  ['simulator', 'What-If Simulator & Service Safety'],
  ['approvals', 'Approvals & Controlled Hardening'],
] as const) {
  test(`@a11y ${route} WCAG A/AA`, async ({ page }, info) => {
    await page.goto(`/orgs/${org}/${route}`);
    await expect(page.getByRole('heading', { name: new RegExp(heading.replace('&', '&')) }).first()).toBeVisible();
    await expect(page.getByText('Loading records...', { exact: true })).toHaveCount(0);
    const results = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).analyze();
    expect(results.violations, JSON.stringify(results.violations.map(v => ({ id: v.id, nodes: v.nodes.map(n => n.target) })))).toEqual([]);
    await expect(page.locator('body')).toHaveJSProperty('scrollWidth', await page.locator('body').evaluate(el => el.clientWidth));
    if (info.project.name === 'desktop-chromium' || route === 'reports') {
      await page.screenshot({ path: path.resolve('../../docs/frontend/screenshots', `phase9-${route}-${info.project.name}.png`), fullPage: true });
    }
  });
}
