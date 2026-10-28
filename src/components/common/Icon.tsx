const PATHS = {
  upload: 'M12 16V4m0 0-4 4m4-4 4 4M4 16v3a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-3',
  overview: 'M4 13h6V4H4zm10 7h6v-9h-6zM4 20h6v-4H4zm10-11h6V4h-6z',
  key: 'M15 7a4 4 0 1 1-3.9 4.9L4 19v-3h2v-2h2l1.2-1.2A4 4 0 0 1 15 7zm1 2h.01',
  globe:
    'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zm0 0c2.5-2.4 3.5-5.6 3.5-9S14.5 5.4 12 3m0 18c-2.5-2.4-3.5-5.6-3.5-9S9.5 5.4 12 3M3.5 9h17M3.5 15h17',
  alert:
    'M12 9v4m0 4h.01M10.3 3.9 2.6 17.3A2 2 0 0 0 4.3 20h15.4a2 2 0 0 0 1.7-2.7L13.7 3.9a2 2 0 0 0-3.4 0z',
  list: 'M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01',
  sliders: 'M4 6h10m4 0h2M4 12h4m4 0h8M4 18h12m4 0h0M14 4v4M8 10v4M16 16v4',
  file: 'M14 3H6a1 1 0 0 0-1 1v16a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V8zm0 0v5h5M9 13h6M9 17h6',
  shield: 'M12 3 4 6v6c0 4.4 3.4 8.3 8 9 4.6-.7 8-4.6 8-9V6z',
  x: 'M6 6l12 12M18 6 6 18',
  search: 'M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14zm9 2-4-4',
  download: 'M12 4v12m0 0-4-4m4 4 4-4M4 20h16',
  check: 'M5 12.5 10 17 19 7',
  table: 'M4 5h16v14H4zM4 10h16M4 15h16M10 5v14',
  chart: 'M4 20V10m6 10V4m6 16v-7m4 7H2',
  filter: 'M4 5h16l-6 8v5l-4 2v-7z',
  clock: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zm0-13v4l3 2',
  refresh: 'M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7',
  info: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zm0-10v5m0-8h.01',
} as const;

export type IconName = keyof typeof PATHS;

/** Decorative inline SVG icon; pair with visible text or an aria-label on the control. */
export function Icon({
  name,
  size = 16,
  className,
}: {
  name: IconName;
  size?: number;
  className?: string;
}) {
  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      <path d={PATHS[name]} />
    </svg>
  );
}
