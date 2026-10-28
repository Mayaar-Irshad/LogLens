# Security

LogLens analyzes untrusted input (log files written by systems an attacker may have touched) inside the analyst's browser. This document describes the threat model, the controls in place, their limits, and how to report a vulnerability.

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub's **Report a vulnerability** button (Security → Advisories) on this repository rather than in a public issue. Include a minimal synthetic log sample that reproduces the problem. Do not attach real production logs.

## Threat model

| Asset                         | Threat                                                                                            | Primary controls                                                                                                              |
| ----------------------------- | ------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| The analyst's browser session | Script injection via crafted log content (usernames, paths, user agents, JSON values, file names) | React text rendering only; no HTML sinks; production CSP; source-hygiene tests                                                |
| Confidentiality of logs       | Logs or indicators leaving the machine                                                            | No network code; `connect-src 'none'`; no analytics, remote fonts or CDNs; no persistence                                     |
| Availability of the tab       | Oversized files, giant lines, deep JSON, billions of repeats                                      | File-size, line-length, event, repeat-expansion and rejected-sample limits; streaming reader; worker timeout and cancellation |
| Integrity of conclusions      | Spoofed fields (e.g. an IP smuggled into a username), invisible characters, misleading results    | Defensive parsing, visible escaping of control/bidi characters, explainable rules with documented limitations                 |
| Exported files                | Spreadsheet formula injection, HTML in JSON                                                       | CSV formula neutralisation; JSON `<`, `>`, `&`, U+2028/2029 escaping; sanitized file names                                    |

## Controls

### Untrusted content is never interpreted

- All log-derived text is rendered as React text nodes. The codebase contains no `dangerouslySetInnerHTML`, `innerHTML`, `insertAdjacentHTML`, `document.write`, `eval` or `new Function`. ESLint rules (`no-restricted-syntax`, `no-restricted-properties`, `no-eval`, `no-new-func`, `@typescript-eslint/no-implied-eval`) and a source-scanning test (`tests/unit/security/sourceHygiene.test.ts`) enforce this.
- URLs found in logs are displayed as text. LogLens never creates links to them and never navigates to them.
- Control characters, zero-width characters and bidirectional overrides (Trojan-Source style text reordering) in extracted fields and original lines are displayed as visible escapes such as `‮` and `\x1b`.
- JSON is parsed with `JSON.parse` and flattened into a `Map`, so keys such as `__proto__` or `constructor` are inert data and cannot affect object prototypes.
- Error messages shown for rejected records never echo the record content. Previews are truncated to 160 characters.

### Parsing defences

- sshd usernames are matched greedily so a username containing `from 1.2.3.4 port 22` cannot spoof the source address; sshd appends the real address last.
- IP addresses are strictly validated and canonicalized (RFC 5952 for IPv6; IPv4-mapped IPv6 is folded to IPv4). Hostnames in IP positions are kept as separate fields and the record is marked partial.
- Timestamps are range-checked component by component; impossible dates are rejected instead of being rolled over by `Date.parse`.
- Ambiguous day/month timestamps (`03/04/2026`) are rejected rather than guessed.

### Resource limits (configurable, validated and clamped)

| Limit                                | Default           | Allowed range   |
| ------------------------------------ | ----------------- | --------------- |
| Maximum input size                   | 25 MB             | 1–200 MB        |
| Maximum line length                  | 16,384 characters | 1,024–262,144   |
| Maximum events analyzed              | 500,000           | 1,000–2,000,000 |
| "message repeated N times" expansion | 1,000 per line    | 1–10,000        |
| Rejected-record samples kept         | 500               | 10–5,000        |
| Analysis timeout                     | 120 s             | 10–900 s        |

Files are streamed in chunks. A line longer than the limit is counted but not buffered, so a multi-megabyte line or a binary file without newlines cannot exhaust memory. Lines after the event limit are counted and reported, not silently dropped. Findings per rule are capped at 500 (the strongest are kept and the cap is reported).

All configuration values that cross a trust boundary (settings form → state → worker message) are validated again inside the worker.

### Web Worker isolation and its limits

Parsing, detection and aggregation run in a dedicated module Web Worker so a large file does not freeze the page, and so cancellation and timeouts can terminate the work instantly (`worker.terminate()`).

**A Web Worker is not a security sandbox.** It runs with the page's origin and could use the same web APIs (including network APIs) if it contained such code. LogLens' safety comes from the code never interpreting log content and never making network requests, not from the worker boundary. Treat the worker as a performance and robustness measure.

### Content Security Policy

The production build injects this policy as a `<meta>` tag:

```
default-src 'none'; script-src 'self'; worker-src 'self'; style-src 'self'; img-src 'self' data:;
font-src 'self'; connect-src 'none'; manifest-src 'self'; base-uri 'none'; form-action 'none'; object-src 'none'
```

Notes:

- `connect-src 'none'` blocks `fetch`, XHR, WebSocket and EventSource from the page. Vite's module-preload polyfill (which uses `fetch`) is disabled for this reason.
- A `<meta>` CSP cannot set `frame-ancestors`, and GitHub Pages does not let you add response headers. If you host LogLens elsewhere, also send the policy as an HTTP header and add `frame-ancestors 'none'`.
- Dedicated workers loaded from a same-origin URL take their policy from their own response headers, not from the page's `<meta>` tag. The worker bundle contains no network code; the source-hygiene test checks for `fetch`, `XMLHttpRequest`, `WebSocket` and `sendBeacon`.
- The development server (`npm run dev`) does not inject the CSP, because Vite's hot-module reload needs inline scripts and a websocket.

### Exports

- CSV: every cell is quoted, quotes are doubled, and cells starting with `=`, `+`, `-`, `@`, tab, carriage return (or their full-width forms) are prefixed with `'` (OWASP CSV-injection guidance).
- JSON: `<`, `>`, `&`, U+2028 and U+2029 are written as `\u` escapes, which keeps the file valid JSON and inert if it is embedded in HTML.
- Original log lines are excluded from reports and CSV exports unless the analyst explicitly ticks the option. The UI warns that they may contain sensitive data.
- File names are derived from the input name with everything outside `[A-Za-z0-9._-]` replaced, then bounded in length.
- Downloads use a temporary `blob:` URL that is revoked right after the click.

## Dependency review

Runtime dependencies are deliberately few: `react`, `react-dom` and `recharts` (whose transitive tree includes `d3-*` modules, `@reduxjs/toolkit`, `immer`, `reselect`, `es-toolkit`, `decimal.js-light`, `eventemitter3` and `victory-vendor`). None of them is used to process log content as markup, and none performs network requests in LogLens' usage. The interface font comes from `@fontsource-variable/public-sans` (SIL OFL 1.1): a stylesheet and WOFF2 files only, with no JavaScript, bundled into `dist/` and served from the app's own origin under `font-src 'self'`. `npm audit` reported 0 known vulnerabilities at the time of writing. Dependabot is configured for npm and GitHub Actions updates.

Build and CI hygiene:

- Exact versions are pinned in `package.json`; `package-lock.json` is committed and CI installs with `npm ci --ignore-scripts`.
- GitHub Actions use the minimum permissions; checkout does not persist credentials.

## Known limitations

- Detections are heuristics. A determined attacker who controls log content can craft entries that evade signatures or create misleading noise; LogLens reports what the logs say, not what happened.
- Anything you include in an exported report leaves LogLens' control: review exports before sharing.
- The in-page fallback (used only if a browser lacks Web Workers) runs analysis on the main thread, so very large files can make the page unresponsive until the timeout.
