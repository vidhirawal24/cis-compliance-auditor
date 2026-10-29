import { z } from 'zod';

export const runtimeConfigSchema = z.object({
  mode: z.enum(['disabled', 'demo', 'http']),
  apiBaseUrl: z.string().default('/api/v1'),
  approvedReads: z.array(z.string()).default([]),
});
export type RuntimeConfig = z.infer<typeof runtimeConfigSchema>;
declare global { interface Window { __BASELINEGUARD_CONFIG__?: unknown } }
export function runtimeConfig(): RuntimeConfig {
  const supplied = window.__BASELINEGUARD_CONFIG__;
  if (supplied !== undefined) {
    const result = runtimeConfigSchema.safeParse(supplied);
    return result.success ? result.data : { mode: 'disabled', apiBaseUrl: '/api/v1', approvedReads: [] };
  }
  // Explicit test/development mode only; ordinary dev and production fail closed.
  return { mode: ['test', 'demo'].includes(import.meta.env.MODE) ? 'demo' : 'disabled', apiBaseUrl: '/api/v1', approvedReads: [] };
}
