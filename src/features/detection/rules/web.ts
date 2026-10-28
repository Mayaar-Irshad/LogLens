import type { Confidence, Severity } from '../../../types/detection';
import type { NormalizedEvent } from '../../../types/events';
import { truncate } from '../../../utils/text';
import { isoUtc, listPreview, minutes, plural, representative, unique } from '../engine/context';
import type { DetectionContext, Finding, RuleDefinition } from '../engine/types';
import {
  findBursts,
  findDistinctBursts,
  groupBy,
  topCounts,
  type TimedRef,
} from '../engine/windows';
import { classifyIp, type IpClass } from '../../log-ingestion/normalization/ip';
import { countParam, SEVERITY_ESCALATION_NOTE, windowParam } from './params';

const INTERNAL_CLASSES = new Set<IpClass>([
  'private',
  'loopback',
  'link-local',
  'unique-local',
  'shared-cgnat',
]);
import {
  matchRequestSignatures,
  matchScannerAgent,
  matchSensitivePath,
  STANDARD_METHODS,
  UNUSUAL_METHODS,
} from './webSignatures';

const MINUTE = 60_000;

const refs = (events: NormalizedEvent[]): TimedRef[] =>
  events.map((e) => ({ t: e.timestamp!, id: e.id }));
const pick = (ctx: DetectionContext, ids: number[]): NormalizedEvent[] =>
  ids.map((id) => ctx.events[id]!);
const status = (e: NormalizedEvent): number | undefined => e.http?.status;
const topList = (values: Array<string | undefined>, n = 5): string =>
  topCounts(values, n)
    .map((c) => `${truncate(c.key, 80)} (${c.count})`)
    .join(', ') || 'none';
const target = (e: NormalizedEvent): string =>
  `${e.http?.path ?? ''}${e.http?.query ? `?${e.http.query}` : ''}`;

const NO_WEB = 'No web requests with timestamps in this dataset.';
const hasTimedWeb = (ctx: DetectionContext): string | null =>
  ctx.timedWebRequests.length > 0 ? null : NO_WEB;

const COMMON_WEB_LIMITATIONS = [
  'Access logs record requests and response codes, not application behaviour; a matching request does not mean an exploit succeeded.',
  'Client addresses can be load balancers or CDNs unless the log records the original client IP.',
  SEVERITY_ESCALATION_NOTE,
];

const UNTIMED_WEB = (ctx: DetectionContext): string[] =>
  ctx.untimed.web > 0
    ? [
        `${plural(ctx.untimed.web, 'web request')} without a valid timestamp were excluded from windowed counting.`,
      ]
    : [];

export const WEB_001: RuleDefinition = {
  id: 'WEB-001',
  name: 'Burst of HTTP 4xx responses from one client',
  category: 'web',
  scope: 'ip',
  description:
    'A single client receives many client-error responses (400–499) in a short window. Common with content discovery, broken crawlers, or credential guessing against web logins (401/403).',
  requires: 'Web requests with status codes, client IPs and timestamps.',
  params: [
    countParam(
      'threshold',
      '4xx responses',
      'Minimum 4xx responses to one client within the window.',
      50,
      2,
    ),
    windowParam(5),
  ],
  recommendations: [
    'Break the burst down by status code: 404s suggest path discovery, 401/403s suggest access attempts.',
    'Review the requested paths for sensitive targets and any 2xx responses from the same client.',
    'Consider rate limiting or blocking the client if it is not a known crawler or monitor.',
  ],
  limitations: COMMON_WEB_LIMITATIONS,
  falsePositives: [
    'Broken links after a deployment',
    'Misconfigured monitoring or crawlers',
    'Single-page apps polling a removed API',
  ],
  mitre: [{ id: 'T1595.003', name: 'Active Scanning: Wordlist Scanning' }],
  applicable: hasTimedWeb,
  evaluate(ctx, p) {
    const threshold = p.threshold!;
    const window = p.windowMinutes!;
    const errors = ctx.timedWebRequests.filter(
      (e) => (status(e) ?? 0) >= 400 && (status(e) ?? 0) < 500,
    );
    const findings: Finding[] = [];
    for (const [ip, events] of groupBy(errors, (e) => e.sourceIp)) {
      for (const b of findBursts(refs(events), window * MINUTE, threshold)) {
        const evs = pick(ctx, b.ids);
        const paths = unique(evs.map((e) => e.http?.path));
        findings.push({
          key: ip,
          severity: b.count >= threshold * 4 ? 'medium' : 'low',
          confidence: b.peak >= threshold * 2 ? 'high' : 'medium',
          title: `Burst of ${b.count} HTTP 4xx responses to ${ip}`,
          reason: `${ip} received ${plural(b.count, '4xx response')} for ${plural(paths.length, 'distinct path')} between ${isoUtc(b.start)} and ${isoUtc(b.end)}. Peak: ${b.peak} within ${minutes(window)}; threshold is ${threshold}.`,
          condition: `HTTP 4xx responses to the same client IP ≥ ${threshold} within ${minutes(window)}`,
          thresholds: [
            { name: '4xx responses', value: threshold, unit: 'events' },
            { name: 'Window', value: window, unit: 'minutes' },
          ],
          metric: b.peak,
          primaryThreshold: threshold,
          eventIds: b.ids,
          sourceIps: [ip],
          usernames: unique(evs.map((e) => e.username)),
          start: b.start,
          end: b.end,
          representativeTimestamps: representative(b.start, b.peakAt, b.end),
          evidence: [
            { label: 'Status codes', value: topList(evs.map((e) => String(status(e)))) },
            { label: 'Top paths', value: topList(evs.map((e) => e.http?.path)) },
            {
              label: 'User agents',
              value: topList(
                evs.map((e) => e.http?.userAgent),
                3,
              ),
            },
          ],
          extraLimitations: UNTIMED_WEB(ctx),
        });
      }
    }
    return findings;
  },
};

export const WEB_002: RuleDefinition = {
  id: 'WEB-002',
  name: 'Burst of HTTP 5xx server errors',
  category: 'web',
  scope: 'global',
  description:
    'Many server-error responses (500–599) across all clients within a window. This usually indicates an application or infrastructure problem, but crafted requests can also trigger server errors.',
  requires: 'Web requests with status codes and timestamps.',
  params: [
    countParam(
      'threshold',
      '5xx responses',
      'Minimum 5xx responses (all clients) within the window.',
      20,
      2,
    ),
    windowParam(5),
  ],
  recommendations: [
    'Correlate with deployments, application error logs and upstream health checks for the same period.',
    'Check whether the errors are concentrated on one path or one client (see evidence).',
    'If one client triggers most errors with unusual input, review those requests for injection attempts (WEB-008).',
  ],
  limitations: COMMON_WEB_LIMITATIONS,
  falsePositives: ['Outages, deployments, overloaded upstreams or database failures.'],
  mitre: [{ id: 'T1190', name: 'Exploit Public-Facing Application' }],
  applicable: hasTimedWeb,
  evaluate(ctx, p) {
    const threshold = p.threshold!;
    const window = p.windowMinutes!;
    const errors = ctx.timedWebRequests.filter((e) => (status(e) ?? 0) >= 500);
    return findBursts(refs(errors), window * MINUTE, threshold).map((b): Finding => {
      const evs = pick(ctx, b.ids);
      const ips = topCounts(
        evs.map((e) => e.sourceIp),
        100,
      );
      const dominant = ips[0];
      const concentrated = dominant !== undefined && dominant.count / evs.length >= 0.8;
      return {
        key: `global:${b.start}`,
        severity: b.count >= threshold * 5 ? 'high' : 'medium',
        confidence: 'medium',
        title: `Burst of ${b.count} HTTP 5xx server errors`,
        reason: `${plural(b.count, 'server error')} between ${isoUtc(b.start)} and ${isoUtc(b.end)} from ${plural(ips.length, 'client')}. Peak: ${b.peak} within ${minutes(window)}; threshold is ${threshold}.${concentrated ? ` ${Math.round((dominant.count / evs.length) * 100)}% came from ${dominant.key}.` : ''}`,
        condition: `HTTP 5xx responses (all clients) ≥ ${threshold} within ${minutes(window)}`,
        thresholds: [
          { name: '5xx responses', value: threshold, unit: 'events' },
          { name: 'Window', value: window, unit: 'minutes' },
        ],
        metric: b.peak,
        primaryThreshold: threshold,
        eventIds: b.ids,
        sourceIps: ips.slice(0, 20).map((i) => i.key),
        usernames: unique(evs.map((e) => e.username)),
        start: b.start,
        end: b.end,
        representativeTimestamps: representative(b.start, b.peakAt, b.end),
        evidence: [
          { label: 'Status codes', value: topList(evs.map((e) => String(status(e)))) },
          { label: 'Top paths', value: topList(evs.map((e) => e.http?.path)) },
          {
            label: 'Top clients',
            value:
              ips
                .slice(0, 5)
                .map((i) => `${i.key} (${i.count})`)
                .join(', ') || 'none',
          },
        ],
        extraLimitations: UNTIMED_WEB(ctx),
      };
    });
  },
};

export const WEB_003: RuleDefinition = {
  id: 'WEB-003',
  name: 'Repeated requests to sensitive paths',
  category: 'web',
  scope: 'ip',
  description:
    'A client repeatedly requests administrative, login, or secret-bearing paths (for example /wp-login.php, /admin, /.env, /.git/). A successful (2xx) response to a secret-bearing path may indicate exposed files.',
  requires: 'Web requests with paths, client IPs and timestamps.',
  params: [
    countParam(
      'threshold',
      'Requests',
      'Minimum sensitive-path requests from one client within the window.',
      5,
      1,
    ),
    windowParam(10),
  ],
  recommendations: [
    'Check every 2xx response in the evidence: confirm the file or panel should be reachable from this client.',
    'If a secret-bearing file (.env, .git, backups) returned 2xx, treat its contents as exposed and rotate any credentials it holds.',
    'Restrict administrative paths by network location or authentication at the proxy.',
  ],
  limitations: [
    ...COMMON_WEB_LIMITATIONS,
    'The sensitive-path list is a fixed, documented set of common targets; application-specific paths are not included.',
  ],
  falsePositives: [
    'Administrators legitimately using admin or login pages',
    'Uptime monitors checking a login page',
  ],
  mitre: [
    { id: 'T1595.003', name: 'Active Scanning: Wordlist Scanning' },
    { id: 'T1083', name: 'File and Directory Discovery' },
  ],
  applicable: hasTimedWeb,
  evaluate(ctx, p) {
    const threshold = p.threshold!;
    const window = p.windowMinutes!;
    const matches = new Map<number, ReturnType<typeof matchSensitivePath>>();
    const sensitive = ctx.timedWebRequests.filter((e) => {
      const m = e.http?.path ? matchSensitivePath(e.http.path) : undefined;
      if (m) matches.set(e.id, m);
      return m !== undefined;
    });
    const findings: Finding[] = [];
    for (const [ip, events] of groupBy(sensitive, (e) => e.sourceIp)) {
      for (const b of findBursts(refs(events), window * MINUTE, threshold)) {
        const evs = pick(ctx, b.ids);
        const kinds = new Set(evs.map((e) => matches.get(e.id)!.kind));
        const exposed = evs.filter(
          (e) =>
            matches.get(e.id)!.kind === 'secret' &&
            (status(e) ?? 0) >= 200 &&
            (status(e) ?? 0) < 300,
        );
        let severity: Severity = kinds.has('secret') ? 'medium' : 'low';
        let confidence: Confidence = 'medium';
        // A 2xx for a secret-bearing path from the internet is the signal. From loopback or
        // private ranges it is usually a probe or an operator, so it stays at medium.
        const internal = INTERNAL_CLASSES.has(classifyIp(ip));
        if (exposed.length > 0 && !internal) {
          severity = 'high';
          confidence = 'high';
        } else if (exposed.length > 0) {
          severity = 'medium';
        }
        findings.push({
          key: ip,
          severity,
          confidence,
          title:
            exposed.length > 0
              ? `Sensitive file served to ${ip}`
              : `Sensitive paths requested by ${ip}`,
          reason: `${ip} made ${plural(b.count, 'request')} to sensitive paths (${[...kinds].join(', ')}) between ${isoUtc(b.start)} and ${isoUtc(b.end)}; threshold is ${threshold} within ${minutes(window)}.${exposed.length > 0 ? ` ${plural(exposed.length, 'request')} for secret-bearing paths received a 2xx response.` : ''}`,
          condition: `requests to the sensitive-path list from the same client ≥ ${threshold} within ${minutes(window)}`,
          thresholds: [
            { name: 'Requests', value: threshold, unit: 'events' },
            { name: 'Window', value: window, unit: 'minutes' },
          ],
          metric: b.peak,
          primaryThreshold: threshold,
          eventIds: b.ids,
          sourceIps: [ip],
          usernames: unique(evs.map((e) => e.username)),
          start: b.start,
          end: b.end,
          representativeTimestamps: representative(b.start, b.peakAt, b.end),
          evidence: [
            {
              label: 'Matched categories',
              value: topList(evs.map((e) => matches.get(e.id)!.label)),
            },
            { label: 'Paths', value: topList(evs.map((e) => e.http?.path)) },
            { label: 'Responses', value: topList(evs.map((e) => String(status(e)))) },
            {
              label: '2xx for secret-bearing paths',
              value:
                exposed.length > 0
                  ? listPreview(
                      unique(exposed.map((e) => e.http?.path)).map((x) => truncate(x, 80)),
                    )
                  : 'none',
            },
          ],
          extraLimitations: UNTIMED_WEB(ctx),
        });
      }
    }
    return findings;
  },
};

export const WEB_004: RuleDefinition = {
  id: 'WEB-004',
  name: 'Directory or path probing',
  category: 'web',
  scope: 'ip',
  description:
    'A client requests many distinct paths that do not exist or are forbidden (404/403/410) in a short window. This is characteristic of content-discovery tools working through a wordlist.',
  requires: 'Web requests with paths, status codes, client IPs and timestamps.',
  params: [
    countParam(
      'minDistinctPaths',
      'Distinct missing paths',
      'Minimum distinct paths answered 403/404/410 for one client within the window.',
      20,
      2,
      100_000,
      'paths',
    ),
    windowParam(5),
  ],
  recommendations: [
    'Review the probed paths to understand what the client was looking for (CMS, backups, admin tools).',
    'Check for any 2xx responses from the same client in the same period; those are the paths it found.',
    'Block or rate limit the client if it is not an authorised scanner.',
  ],
  limitations: COMMON_WEB_LIMITATIONS,
  falsePositives: [
    'Search-engine crawlers following stale links',
    'Authorised vulnerability scans',
  ],
  mitre: [{ id: 'T1595.003', name: 'Active Scanning: Wordlist Scanning' }],
  applicable: hasTimedWeb,
  evaluate(ctx, p) {
    const minPaths = p.minDistinctPaths!;
    const window = p.windowMinutes!;
    const missing = ctx.timedWebRequests.filter(
      (e) => [403, 404, 410].includes(status(e) ?? 0) && e.http?.path,
    );
    const findings: Finding[] = [];
    for (const [ip, events] of groupBy(missing, (e) => e.sourceIp)) {
      const items = events.map((e) => ({ t: e.timestamp!, id: e.id, key: e.http!.path! }));
      for (const b of findDistinctBursts(items, window * MINUTE, minPaths)) {
        const evs = pick(ctx, b.ids);
        const paths = unique(evs.map((e) => e.http?.path));
        findings.push({
          key: ip,
          severity: paths.length >= minPaths * 5 ? 'high' : 'medium',
          confidence: b.peak >= minPaths * 2 ? 'high' : 'medium',
          title: `Path probing from ${ip}: ${paths.length} missing paths`,
          reason: `${ip} requested ${plural(paths.length, 'distinct path')} that returned 403/404/410 between ${isoUtc(b.start)} and ${isoUtc(b.end)}. Peak: ${b.peak} distinct paths within ${minutes(window)}; threshold is ${minPaths}.`,
          condition: `distinct paths answered 403/404/410 for the same client ≥ ${minPaths} within ${minutes(window)}`,
          thresholds: [
            { name: 'Distinct missing paths', value: minPaths, unit: 'paths' },
            { name: 'Window', value: window, unit: 'minutes' },
          ],
          metric: b.peak,
          primaryThreshold: minPaths,
          eventIds: b.ids,
          sourceIps: [ip],
          usernames: unique(evs.map((e) => e.username)),
          start: b.start,
          end: b.end,
          representativeTimestamps: representative(b.start, b.peakAt, b.end),
          evidence: [
            {
              label: 'Sample paths',
              value: listPreview(
                paths.map((x) => truncate(x, 60)),
                10,
              ),
            },
            {
              label: 'User agents',
              value: topList(
                evs.map((e) => e.http?.userAgent),
                3,
              ),
            },
          ],
          extraLimitations: UNTIMED_WEB(ctx),
        });
      }
    }
    return findings;
  },
};

export const WEB_005: RuleDefinition = {
  id: 'WEB-005',
  name: 'Suspicious HTTP method patterns',
  category: 'web',
  scope: 'ip',
  description:
    'A client uses rarely needed HTTP methods (TRACE, TRACK, CONNECT, DEBUG, WebDAV methods), non-standard method tokens, or sends request lines that are not valid HTTP (for example TLS handshakes to a plain-HTTP port).',
  requires: 'Web requests with client IPs. Timestamps are not required.',
  params: [
    countParam(
      'threshold',
      'Requests',
      'Minimum suspicious-method requests from one client (whole dataset).',
      1,
      1,
    ),
  ],
  recommendations: [
    'Confirm whether WebDAV or proxying is intentionally enabled on this server.',
    'Check whether TRACE/TRACK/CONNECT received a 2xx response; disable them if so.',
    'Malformed request lines are often port scanners or protocol mismatches and are usually low risk.',
  ],
  limitations: [
    'Some applications use WebDAV legitimately; method lists are generic.',
    'Not windowed: counts suspicious requests across the whole dataset per client.',
  ],
  falsePositives: [
    'WebDAV clients (file sync tools)',
    'Health checks speaking the wrong protocol',
    'Corporate proxies issuing CONNECT',
  ],
  mitre: [{ id: 'T1595.002', name: 'Active Scanning: Vulnerability Scanning' }],
  applicable: (ctx) => (ctx.webRequests.length > 0 ? null : 'No web requests in this dataset.'),
  evaluate(ctx, p) {
    const threshold = p.threshold!;
    const classify = (e: NormalizedEvent): string | undefined => {
      if (e.issues?.includes('malformed request line')) return 'malformed request line';
      const m = e.http?.method;
      if (!m) return undefined;
      if (UNUSUAL_METHODS.has(m)) return m;
      if (!STANDARD_METHODS.has(m)) return `non-standard method ${truncate(m, 20)}`;
      return undefined;
    };
    const labels = new Map<number, string>();
    const suspicious = ctx.webRequests.filter((e) => {
      const label = classify(e);
      if (label) labels.set(e.id, label);
      return label !== undefined;
    });
    const findings: Finding[] = [];
    for (const [ip, evs] of groupBy(suspicious, (e) => e.sourceIp)) {
      if (evs.length < threshold) continue;
      const risky = evs.filter(
        (e) =>
          ['TRACE', 'TRACK', 'CONNECT', 'DEBUG'].includes(e.http?.method ?? '') &&
          (status(e) ?? 0) >= 200 &&
          (status(e) ?? 0) < 300,
      );
      const times = evs
        .map((e) => e.timestamp)
        .filter((t): t is number => t !== undefined)
        .sort((a, b) => a - b);
      const start = times[0];
      const end = times[times.length - 1];
      const onlyMalformed = evs.every((e) => labels.get(e.id) === 'malformed request line');
      findings.push({
        key: ip,
        severity: risky.length > 0 || evs.length >= 10 ? 'medium' : onlyMalformed ? 'info' : 'low',
        confidence: onlyMalformed ? 'medium' : 'high',
        title: `Suspicious HTTP methods from ${ip}`,
        reason: `${ip} sent ${plural(evs.length, 'request')} with unusual or invalid methods (${topList(evs.map((e) => labels.get(e.id)))}); threshold is ${threshold}.${risky.length > 0 ? ` ${plural(risky.length, 'TRACE/TRACK/CONNECT/DEBUG request')} received a 2xx response.` : ''}`,
        condition: `requests with unusual, non-standard or malformed methods from the same client ≥ ${threshold}`,
        thresholds: [{ name: 'Requests', value: threshold, unit: 'events' }],
        metric: evs.length,
        primaryThreshold: threshold,
        eventIds: evs.map((e) => e.id),
        sourceIps: [ip],
        usernames: unique(evs.map((e) => e.username)),
        ...(start !== undefined ? { start } : {}),
        ...(end !== undefined ? { end } : {}),
        representativeTimestamps:
          start !== undefined && end !== undefined ? [...new Set([start, end])] : [],
        evidence: [
          { label: 'Methods', value: topList(evs.map((e) => labels.get(e.id))) },
          { label: 'Responses', value: topList(evs.map((e) => String(status(e) ?? 'none'))) },
        ],
      });
    }
    return findings;
  },
};

export const WEB_006: RuleDefinition = {
  id: 'WEB-006',
  name: 'Excessive request volume from one client',
  category: 'web',
  scope: 'ip',
  description:
    'A single client sends more requests within the window than the configured limit (possible scraping, flooding, or aggressive automation).',
  requires: 'Web requests with client IPs and timestamps.',
  params: [
    countParam(
      'threshold',
      'Requests',
      'Minimum requests from one client within the window.',
      300,
      2,
    ),
    windowParam(1, 60),
  ],
  recommendations: [
    'Check whether the client is a known crawler, monitor, or internal service.',
    'Review the error ratio and requested paths; scraping and flooding look different.',
    'Apply per-client rate limits at the proxy or CDN if the volume is unwanted.',
  ],
  limitations: [
    ...COMMON_WEB_LIMITATIONS,
    'Load balancers or CDNs in front of the server can make many users appear as one client.',
  ],
  falsePositives: [
    'Search-engine crawlers',
    'API clients with legitimate high throughput',
    'Load tests',
  ],
  mitre: [{ id: 'T1498', name: 'Network Denial of Service' }],
  applicable: hasTimedWeb,
  evaluate(ctx, p) {
    const threshold = p.threshold!;
    const window = p.windowMinutes!;
    const findings: Finding[] = [];
    for (const [ip, events] of groupBy(ctx.timedWebRequests, (e) => e.sourceIp)) {
      for (const b of findBursts(refs(events), window * MINUTE, threshold)) {
        const evs = pick(ctx, b.ids);
        const errors = evs.filter((e) => (status(e) ?? 0) >= 400).length;
        findings.push({
          key: ip,
          severity: b.peak >= threshold * 5 ? 'medium' : 'low',
          confidence: 'high',
          title: `High request volume from ${ip}`,
          reason: `${ip} sent ${plural(b.count, 'request')} between ${isoUtc(b.start)} and ${isoUtc(b.end)}. Peak: ${b.peak} within ${minutes(window)}; threshold is ${threshold}. ${Math.round((errors / evs.length) * 100)}% received an error response.`,
          condition: `requests from the same client ≥ ${threshold} within ${minutes(window)}`,
          thresholds: [
            { name: 'Requests', value: threshold, unit: 'events' },
            { name: 'Window', value: window, unit: 'minutes' },
          ],
          metric: b.peak,
          primaryThreshold: threshold,
          eventIds: b.ids,
          sourceIps: [ip],
          usernames: unique(evs.map((e) => e.username)),
          start: b.start,
          end: b.end,
          representativeTimestamps: representative(b.start, b.peakAt, b.end),
          evidence: [
            { label: 'Peak rate', value: `${b.peak} per ${minutes(window)}` },
            { label: 'Distinct paths', value: String(unique(evs.map((e) => e.http?.path)).length) },
            {
              label: 'Error responses',
              value: `${errors} (${Math.round((errors / evs.length) * 100)}%)`,
            },
            {
              label: 'User agents',
              value: topList(
                evs.map((e) => e.http?.userAgent),
                3,
              ),
            },
          ],
          extraLimitations: UNTIMED_WEB(ctx),
        });
      }
    }
    return findings;
  },
};

export const WEB_007: RuleDefinition = {
  id: 'WEB-007',
  name: 'Repeated requests producing errors',
  category: 'web',
  scope: 'ip',
  description:
    'The same client repeats the same request (method and path) and keeps receiving errors (status ≥ 400). Repeated POSTs to a login endpoint are counted whatever the status, because many applications (WordPress, for example) answer a failed login with 200.',
  requires: 'Web requests with method, path, status code, client IP and timestamp.',
  params: [
    countParam(
      'threshold',
      'Error responses',
      'Minimum error responses for the same client, method and path within the window.',
      10,
      2,
    ),
    windowParam(10),
  ],
  recommendations: [
    'For login endpoints: check application logs for the usernames involved and for any later successful login from the client.',
    'For other paths: the client may be a broken integration retrying; contact the owner if known.',
  ],
  limitations: COMMON_WEB_LIMITATIONS,
  falsePositives: [
    'Integrations retrying with an expired token',
    'Health checks against a broken endpoint',
  ],
  mitre: [{ id: 'T1110', name: 'Brute Force' }],
  applicable: hasTimedWeb,
  evaluate(ctx, p) {
    const threshold = p.threshold!;
    const window = p.windowMinutes!;
    const loginPost = (e: NormalizedEvent): boolean =>
      e.http?.method === 'POST' && matchSensitivePath(e.http.path ?? '')?.kind === 'auth';
    const errors = ctx.timedWebRequests.filter(
      (e) => e.sourceIp && e.http?.path && ((status(e) ?? 0) >= 400 || loginPost(e)),
    );
    const findings: Finding[] = [];
    for (const [key, events] of groupBy(
      errors,
      (e) => `${e.sourceIp} ${e.http?.method ?? '-'} ${e.http!.path!}`,
    )) {
      for (const b of findBursts(refs(events), window * MINUTE, threshold)) {
        const evs = pick(ctx, b.ids);
        const first = evs[0]!;
        const path = first.http!.path!;
        const sensitive = matchSensitivePath(path);
        const authErrors = evs.filter((e) => [401, 403].includes(status(e) ?? 0)).length;
        const loginGuessing =
          sensitive?.kind === 'auth' && (authErrors / evs.length >= 0.5 || loginPost(first));
        const serverErrors = evs.filter((e) => (status(e) ?? 0) >= 500).length;
        findings.push({
          key,
          severity: loginGuessing || serverErrors / evs.length >= 0.5 ? 'medium' : 'low',
          confidence: 'medium',
          title: loginGuessing
            ? `Repeated login attempts to ${truncate(path, 60)} from ${first.sourceIp}`
            : `Repeated failing requests to ${truncate(path, 60)} from ${first.sourceIp}`,
          reason: `${first.sourceIp} sent ${first.http?.method ?? 'requests'} ${truncate(path, 120)} ${b.count} times with error responses between ${isoUtc(b.start)} and ${isoUtc(b.end)}. Peak: ${b.peak} within ${minutes(window)}; threshold is ${threshold}.`,
          condition: `error responses (status ≥ 400), or POSTs to a login endpoint, for the same client, method and path ≥ ${threshold} within ${minutes(window)}`,
          thresholds: [
            { name: 'Error responses', value: threshold, unit: 'events' },
            { name: 'Window', value: window, unit: 'minutes' },
          ],
          metric: b.peak,
          primaryThreshold: threshold,
          eventIds: b.ids,
          sourceIps: [first.sourceIp!],
          usernames: unique(evs.map((e) => e.username)),
          start: b.start,
          end: b.end,
          representativeTimestamps: representative(b.start, b.peakAt, b.end),
          evidence: [
            { label: 'Request', value: `${first.http?.method ?? '-'} ${truncate(path, 120)}` },
            { label: 'Responses', value: topList(evs.map((e) => String(status(e)))) },
            { label: 'Login endpoint', value: sensitive?.kind === 'auth' ? 'yes' : 'no' },
          ],
          extraLimitations: UNTIMED_WEB(ctx),
        });
      }
    }
    return findings;
  },
};

export const WEB_008: RuleDefinition = {
  id: 'WEB-008',
  name: 'Injection or traversal patterns in requests',
  category: 'web',
  scope: 'ip',
  description:
    'Request paths, query strings, or user agents contain well-known attack signatures: path traversal, sensitive file inclusion, SQL injection, cross-site scripting, command injection, JNDI lookups (Log4Shell) or Shellshock.',
  requires: 'Web requests with paths or user agents. Timestamps are not required.',
  params: [
    countParam(
      'threshold',
      'Matching requests',
      'Minimum signature-matching requests from one client (whole dataset).',
      1,
      1,
    ),
  ],
  recommendations: [
    'Check the response codes: 4xx usually means the request was refused; 2xx or 5xx deserve a closer look in application logs.',
    'Verify the targeted component is patched against the matched technique (e.g. Log4j for JNDI lookups).',
    'Search for the same client in other logs (WAF, application, database).',
  ],
  limitations: [
    'Signatures are simple regular expressions over decoded text; encoding tricks can evade them and benign data can match them.',
    'A match shows intent in the request, not that the application was vulnerable.',
    'Not windowed: counts matching requests across the whole dataset per client.',
  ],
  falsePositives: [
    'Security scanners run by your own team',
    'Search queries that contain SQL or HTML words',
    'Content-management tools that post markup',
  ],
  mitre: [
    { id: 'T1190', name: 'Exploit Public-Facing Application' },
    { id: 'T1595.002', name: 'Active Scanning: Vulnerability Scanning' },
  ],
  applicable: (ctx) => (ctx.webRequests.length > 0 ? null : 'No web requests in this dataset.'),
  evaluate(ctx, p) {
    const threshold = p.threshold!;
    const matchesById = new Map<number, ReturnType<typeof matchRequestSignatures>>();
    const matching = ctx.webRequests.filter((e) => {
      const m = matchRequestSignatures(target(e), e.http?.userAgent, e.http?.referrer);
      if (m.length > 0) matchesById.set(e.id, m);
      return m.length > 0;
    });
    const findings: Finding[] = [];
    for (const [ip, evs] of groupBy(matching, (e) => e.sourceIp ?? 'unknown client')) {
      if (evs.length < threshold) continue;
      const labels = evs.flatMap((e) => matchesById.get(e.id)!.map((m) => m.signature.label));
      const critical = evs.some((e) => matchesById.get(e.id)!.some((m) => m.signature.critical));
      const succeeded = evs.filter((e) => (status(e) ?? 0) >= 200 && (status(e) ?? 0) < 300).length;
      const times = evs
        .map((e) => e.timestamp)
        .filter((t): t is number => t !== undefined)
        .sort((a, b) => a - b);
      const start = times[0];
      const end = times[times.length - 1];
      findings.push({
        key: ip,
        severity: critical || succeeded > 0 ? 'high' : 'medium',
        confidence: evs.length >= 3 ? 'high' : 'medium',
        title: `Attack signatures in requests from ${ip}`,
        reason: `${ip} sent ${plural(evs.length, 'request')} matching attack signatures (${topList(labels)}); threshold is ${threshold}. ${succeeded} received a 2xx response.`,
        condition: `requests matching the signature list from the same client ≥ ${threshold}`,
        thresholds: [{ name: 'Matching requests', value: threshold, unit: 'events' }],
        metric: evs.length,
        primaryThreshold: threshold,
        eventIds: evs.map((e) => e.id),
        sourceIps: ip === 'unknown client' ? [] : [ip],
        usernames: unique(evs.map((e) => e.username)),
        ...(start !== undefined ? { start } : {}),
        ...(end !== undefined ? { end } : {}),
        representativeTimestamps:
          start !== undefined && end !== undefined ? [...new Set([start, end])] : [],
        evidence: [
          { label: 'Techniques', value: topList(labels) },
          { label: 'Responses', value: topList(evs.map((e) => String(status(e) ?? 'none'))) },
          { label: 'Example request', value: truncate(target(evs[0]!), 160) },
        ],
      });
    }
    return findings;
  },
};

export const WEB_009: RuleDefinition = {
  id: 'WEB-009',
  name: 'Known scanner or attack-tool user agent',
  category: 'web',
  scope: 'ip',
  description:
    'Requests whose User-Agent names a common scanning or attack tool (sqlmap, Nikto, Nuclei, Gobuster, …) or an internet-measurement scanner. User agents are trivially spoofed, so this is context, not proof.',
  requires: 'Web requests with user agents and client IPs. Timestamps are not required.',
  params: [
    countParam(
      'threshold',
      'Requests',
      'Minimum requests with a scanner user agent from one client (whole dataset).',
      1,
      1,
    ),
  ],
  recommendations: [
    'Check whether the scan was authorised (internal security team, contracted test).',
    'Review the other detections for the same client to see what the tool found.',
  ],
  limitations: [
    'Attackers can set any user agent, and real tools often impersonate browsers; absence of a match means nothing.',
  ],
  falsePositives: ['Authorised vulnerability scans', 'Research scanners that announce themselves'],
  mitre: [{ id: 'T1595', name: 'Active Scanning' }],
  applicable: (ctx) =>
    ctx.webRequests.some((e) => e.http?.userAgent) ? null : 'No web requests with user agents.',
  evaluate(ctx, p) {
    const threshold = p.threshold!;
    const agents = new Map<number, ReturnType<typeof matchScannerAgent>>();
    const hits = ctx.webRequests.filter((e) => {
      const m = matchScannerAgent(e.http?.userAgent);
      if (m) agents.set(e.id, m);
      return m !== undefined;
    });
    const findings: Finding[] = [];
    for (const [ip, evs] of groupBy(hits, (e) => e.sourceIp)) {
      if (evs.length < threshold) continue;
      const tools = unique(evs.map((e) => agents.get(e.id)!.label));
      const research = evs.every((e) => agents.get(e.id)!.research);
      const times = evs
        .map((e) => e.timestamp)
        .filter((t): t is number => t !== undefined)
        .sort((a, b) => a - b);
      const start = times[0];
      const end = times[times.length - 1];
      findings.push({
        key: ip,
        severity: research ? 'info' : 'low',
        confidence: 'low',
        title: `Scanner user agent from ${ip}: ${listPreview(tools, 3)}`,
        reason: `${ip} sent ${plural(evs.length, 'request')} with user agents matching ${listPreview(tools, 5)}; threshold is ${threshold}. User agents can be forged.`,
        condition: `requests with a user agent from the scanner list from the same client ≥ ${threshold}`,
        thresholds: [{ name: 'Requests', value: threshold, unit: 'events' }],
        metric: evs.length,
        primaryThreshold: threshold,
        eventIds: evs.map((e) => e.id),
        sourceIps: [ip],
        usernames: unique(evs.map((e) => e.username)),
        ...(start !== undefined ? { start } : {}),
        ...(end !== undefined ? { end } : {}),
        representativeTimestamps:
          start !== undefined && end !== undefined ? [...new Set([start, end])] : [],
        evidence: [
          { label: 'Tools', value: listPreview(tools, 5) },
          {
            label: 'User agents',
            value: topList(
              evs.map((e) => e.http?.userAgent),
              3,
            ),
          },
        ],
      });
    }
    return findings;
  },
};

export const WEB_RULES: RuleDefinition[] = [
  WEB_001,
  WEB_002,
  WEB_003,
  WEB_004,
  WEB_005,
  WEB_006,
  WEB_007,
  WEB_008,
  WEB_009,
];
