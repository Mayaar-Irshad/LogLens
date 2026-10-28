# Privacy

LogLens is designed so that your logs never leave your device.

## What LogLens does with your data

- **Processing happens locally.** Files you select or paste are read by JavaScript running in your browser tab, inside a Web Worker. They are never uploaded.
- **No network requests with log data.** LogLens contains no code that sends data anywhere. The production build's Content-Security-Policy sets `connect-src 'none'`, so the page cannot make `fetch`, XHR or WebSocket requests even by accident. The only network activity is your browser downloading LogLens' own static files from the site that hosts it.
- **No external lookups.** There is no IP reputation, geolocation, WHOIS or threat-intelligence service. IP "classifications" (private, documentation, public…) are computed locally from the address itself.
- **No analytics, tracking, remote fonts or third-party scripts.** The interface font (Public Sans) is bundled with the app and loaded from the same place as the app itself; no font is fetched from a third party.
- **Nothing is persisted.** LogLens does not write logs, parsed events, findings, notes or settings to `localStorage`, `sessionStorage`, IndexedDB, Cache Storage or cookies. Closing or reloading the tab discards everything. Starting a new scan discards the previous dataset, review statuses and notes.
- **Investigation notes and review status** are held in memory only, for the current tab.

## Exports

Reports (JSON) and event exports (CSV) are generated in the browser and downloaded only when you click a download button.

- Original log lines are **excluded by default**. They are only included if you explicitly tick the corresponding option.
- Reports do contain indicators by design: IP addresses, usernames, timestamps, paths and counts. Treat exported files with the same care as the logs themselves.
- Analyst notes are included in reports unless you untick "Include review status and analyst notes".

## Hosting

When LogLens is served from GitHub Pages (or any static host), that host can see that your browser requested LogLens' static files, as with any website. It cannot see the files you analyze.

## Sample data

The bundled samples are synthetic. They are generated deterministically in the browser and use only IP addresses from the IETF documentation ranges (RFC 5737: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and fictional names. They do not contain real log data.

## Contributing test data

Never commit real logs to this repository, including in tests or issues. Use synthetic data and documentation IP ranges.
