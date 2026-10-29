import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './index.css';
import { runtimeConfigSchema } from './api/config';

async function start() {
  if (!['demo', 'test'].includes(import.meta.env.MODE)) {
    try {
      const response = await fetch('/baselineguard-config.json', { cache: 'no-store', signal: AbortSignal.timeout(5000) });
      window.__BASELINEGUARD_CONFIG__ = response.ok ? runtimeConfigSchema.parse(await response.json()) : { mode: 'disabled' };
    } catch { window.__BASELINEGUARD_CONFIG__ = { mode: 'disabled' }; }
  }
  ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
}
void start();

