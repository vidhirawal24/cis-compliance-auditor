import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

const org = 'e9c80d50-1011-42e1-88f2-aa11bb22cc01';
const screens = [
  ['/auth/login', 'Sign In to Workspace'], ['/orgs', 'Select Tenant Workspace'],
  ...[
    ['overview', 'Security Posture & Compliance Overview'], ['assets', 'Asset Inventory (E01)'],
    ['assets/a01-win11-corp-01', 'Device Specification & Collector Facts'], ['scans', 'Audit Scan Center (M13, E04, E18)'],
    ['policies', 'CIS Policy & Benchmark Library (M17, M18, M19)'], ['exceptions', 'Exceptions & Manual Reviews (E12, E14)'],
    ['findings', 'Findings & Compliance Evidence Explorer'], ['graph', 'Cross-Layer Security & Topology Graph'],
    ['risk-scenarios', 'Correlated Risk Scenarios'], ['planner', 'Remediation Planner & Sequence DAG'],
    ['simulator', 'What-If Simulator & Service Safety'], ['approvals', 'Approvals & Controlled Hardening'],
    ['verifications', 'Dual Verification & Proof Dossier'], ['reports', 'Compliance Reports & Drift Timeline'],
    ['notifications', 'Alerts & Integration Delivery'], ['admin/users', 'Administration & Security Governance'],
    ['system-states', 'System States & Edge Case Gallery'],
  ].map(([route, title]) => [`/orgs/${org}/${route}`, title]),
];

test('all 19 guide screen families are reachable at this viewport', async ({ page }) => {
  for (const [route, title] of screens) {
    await page.goto(route);
    await expect(page.getByText(title, { exact: false }).first()).toBeVisible();
    await expect(page.getByText('Loading screen...', { exact: true })).toHaveCount(0);
  }
});

test('findings filters and keyboard selection expose the selected result', async ({ page }) => {
  await page.goto(`/orgs/${org}/findings`);
  await expect(page.getByLabel('Filter findings by status')).toBeVisible();
  const result = page.getByRole('region', { name: 'Finding results', exact: true }).getByRole('button').nth(1);
  await result.focus(); await page.keyboard.press('Enter');
  await expect(result).toHaveAttribute('aria-pressed', 'true');
  await page.getByLabel('Filter findings by status').selectOption('ERROR');
  await expect(page.getByText('Check Point Web Management HTTPS TLS Cipher Suite Assessment', { exact: false }).first()).toBeVisible();
  await expect(page.getByRole('region', { name: 'Finding results', exact: true }).getByRole('button')).toHaveCount(1);
});

for (const route of ['policies', 'findings', 'planner', 'verifications', 'notifications', 'admin/users']) {
  test(`@a11y regression ${route}`, async ({ page }) => {
    await page.goto(`/orgs/${org}/${route}`);
    await expect(page.getByRole('heading').first()).toBeVisible();
    await expect(page.getByText('Loading screen...', { exact: true })).toHaveCount(0);
    await expect(page.getByText('Loading records...', { exact: true })).toHaveCount(0);
    const result = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).analyze();
    expect(result.violations, JSON.stringify(result.violations.map(v => ({ id: v.id, nodes: v.nodes.map(n => n.target) })))).toEqual([]);
  });
}
