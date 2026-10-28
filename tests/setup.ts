import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
import { afterEach } from 'vitest';

afterEach(() => {
  cleanup();
  // Views are mirrored in the URL hash; start every test from a clean URL.
  window.history.replaceState(null, '', '/');
});

// jsdom has no layout engine; Recharts' ResponsiveContainer only needs the API to exist.
class ResizeObserverStub {
  observe(): void {}
  unobserve(): void {}
  disconnect(): void {}
}
globalThis.ResizeObserver ??= ResizeObserverStub as unknown as typeof ResizeObserver;
