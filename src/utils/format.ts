import type { DisplayTimeZone } from '../types/analytics';

const pad = (n: number, width = 2): string => String(n).padStart(width, '0');

interface DateParts {
  year: number;
  month: number;
  day: number;
  hour: number;
  minute: number;
  second: number;
}

function partsFor(ms: number, tz: DisplayTimeZone): DateParts {
  const d = new Date(ms);
  return tz === 'UTC'
    ? {
        year: d.getUTCFullYear(),
        month: d.getUTCMonth() + 1,
        day: d.getUTCDate(),
        hour: d.getUTCHours(),
        minute: d.getUTCMinutes(),
        second: d.getUTCSeconds(),
      }
    : {
        year: d.getFullYear(),
        month: d.getMonth() + 1,
        day: d.getDate(),
        hour: d.getHours(),
        minute: d.getMinutes(),
        second: d.getSeconds(),
      };
}

/** Minutes east of UTC for the given instant in the display time zone. */
export function displayOffsetMinutes(ms: number, tz: DisplayTimeZone): number {
  return tz === 'UTC' ? 0 : -new Date(ms).getTimezoneOffset();
}

export function formatOffset(minutes: number): string {
  if (minutes === 0) return 'UTC';
  const sign = minutes > 0 ? '+' : '-';
  const abs = Math.abs(minutes);
  return `UTC${sign}${pad(Math.floor(abs / 60))}:${pad(abs % 60)}`;
}

/** "2026-10-27 14:05:09 UTC" style timestamp in the display zone. */
export function formatTimestamp(ms: number | undefined, tz: DisplayTimeZone): string {
  if (ms === undefined || !Number.isFinite(ms)) return '—';
  const p = partsFor(ms, tz);
  const zone = tz === 'UTC' ? 'UTC' : formatOffset(displayOffsetMinutes(ms, tz));
  return `${p.year}-${pad(p.month)}-${pad(p.day)} ${pad(p.hour)}:${pad(p.minute)}:${pad(p.second)} ${zone}`;
}

/** "10-27 00:24 UTC": month-day and minutes, for tight spaces such as KPI sublines. */
export function formatShortTimestamp(ms: number | undefined, tz: DisplayTimeZone): string {
  if (ms === undefined || !Number.isFinite(ms)) return '—';
  const p = partsFor(ms, tz);
  const zone = tz === 'UTC' ? 'UTC' : 'local';
  return `${pad(p.month)}-${pad(p.day)} ${pad(p.hour)}:${pad(p.minute)} ${zone}`;
}

/** Compact label for chart axes. Includes the date only when the span crosses days. */
export function formatAxisTime(ms: number, tz: DisplayTimeZone, spanMs: number): string {
  const p = partsFor(ms, tz);
  const time = `${pad(p.hour)}:${pad(p.minute)}`;
  if (spanMs <= 24 * 3600_000) return time;
  if (spanMs <= 14 * 24 * 3600_000) return `${pad(p.month)}-${pad(p.day)} ${time}`;
  return `${p.year}-${pad(p.month)}-${pad(p.day)}`;
}

/** Value for <input type="datetime-local"> in the display zone. */
export function toDateTimeInput(ms: number | undefined, tz: DisplayTimeZone): string {
  if (ms === undefined || !Number.isFinite(ms)) return '';
  const p = partsFor(ms, tz);
  return `${p.year}-${pad(p.month)}-${pad(p.day)}T${pad(p.hour)}:${pad(p.minute)}:${pad(p.second)}`;
}

/** Parse a datetime-local input value interpreted in the display zone. */
export function fromDateTimeInput(value: string, tz: DisplayTimeZone): number | undefined {
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?$/.exec(value);
  if (!m) return undefined;
  const [y, mo, d, h, mi, s] = [m[1], m[2], m[3], m[4], m[5], m[6] ?? '0'].map(Number) as [
    number,
    number,
    number,
    number,
    number,
    number,
  ];
  const ms =
    tz === 'UTC' ? Date.UTC(y, mo - 1, d, h, mi, s) : new Date(y, mo - 1, d, h, mi, s).getTime();
  return Number.isFinite(ms) ? ms : undefined;
}

export function formatDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return '—';
  const sec = Math.round(ms / 1000);
  if (sec < 60) return `${sec}s`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ${pad(sec % 60)}s`;
  const hr = Math.floor(min / 60);
  if (hr < 48) return `${hr}h ${pad(min % 60)}m`;
  return `${Math.floor(hr / 24)}d ${hr % 24}h`;
}

export function formatNumber(n: number): string {
  return new Intl.NumberFormat('en-US').format(n);
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function formatPercent(part: number, total: number): string {
  if (total <= 0) return '0%';
  const pct = (part / total) * 100;
  return `${pct < 10 && pct > 0 ? pct.toFixed(1) : Math.round(pct)}%`;
}

export const MINUTE_MS = 60_000;
export const HOUR_MS = 3_600_000;
export const DAY_MS = 86_400_000;
