import { useEffect, useEffectEvent, useState } from 'react';

export interface QueryState<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
}

interface Settled<T> {
  key: string | null;
  data: T | null;
  error: string | null;
}

/**
 * Run an asynchronous worker query whenever `key` changes. Each result is
 * stored with the key it answers, so a slow response for a superseded key can
 * never be shown as current. While a new key is loading, the previous data
 * stays visible and `loading` is true. A null key disables the query.
 */
export function useWorkerQuery<T>(
  key: string | null,
  run: () => Promise<T>,
  debounceMs = 0,
): QueryState<T> {
  const [settled, setSettled] = useState<Settled<T>>({ key: null, data: null, error: null });
  const execute = useEffectEvent(() => run());

  useEffect(() => {
    if (key === null) return;
    let cancelled = false;
    const timer = setTimeout(() => {
      execute().then(
        (data) => {
          if (!cancelled) setSettled({ key, data, error: null });
        },
        (error: unknown) => {
          if (!cancelled)
            setSettled({
              key,
              data: null,
              error: error instanceof Error ? error.message : 'Query failed.',
            });
        },
      );
    }, debounceMs);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [key, debounceMs]);

  if (key === null) return { data: null, loading: false, error: null };
  const current = settled.key === key;
  return { data: settled.data, loading: !current, error: current ? settled.error : null };
}
