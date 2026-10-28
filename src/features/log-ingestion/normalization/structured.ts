import type { AuthOutcome, EventCategory, EventDraft, HttpDetails } from '../../../types/events';
import type { FieldMapping, MappableField, TimestampOptions } from '../../../types/ingestion';
import { cleanField, normalizeKey, toActionLabel, truncate } from '../../../utils/text';
import { normalizeIp } from './ip';
import { inferCategoryFromText, inferOutcomeFromText, normalizeOutcome } from './outcome';
import { parseFlexibleTimestamp } from './timestamp';

export type FieldValue = string | number | boolean;

/**
 * A flattened structured record. A Map (rather than a plain object) is used so
 * that untrusted keys such as "__proto__" or "constructor" are inert data.
 */
export type FlatRecord = Map<string, FieldValue>;

export const MAX_FLAT_FIELDS = 200;
const MAX_EXTRA_FIELDS = 40;

/** Flatten nested JSON into dotted keys, bounded in depth and field count. */
export function flattenObject(obj: Record<string, unknown>, maxDepth = 4): FlatRecord {
  const out: FlatRecord = new Map();
  const walk = (value: unknown, prefix: string, depth: number): void => {
    if (out.size >= MAX_FLAT_FIELDS) return;
    if (value === null || value === undefined) return;
    if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
      out.set(prefix, value);
      return;
    }
    if (Array.isArray(value)) {
      const primitives = value.every(
        (v) => typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean',
      );
      out.set(
        prefix,
        primitives
          ? truncate(value.slice(0, 20).map(String).join(', '), 512)
          : truncate(JSON.stringify(value), 512),
      );
      return;
    }
    if (typeof value === 'object') {
      if (depth >= maxDepth) {
        out.set(prefix, truncate(JSON.stringify(value), 512));
        return;
      }
      for (const key of Object.keys(value)) {
        walk((value as Record<string, unknown>)[key], prefix ? `${prefix}.${key}` : key, depth + 1);
      }
    }
  };
  walk(obj, '', 0);
  return out;
}

const SYNONYMS: Record<MappableField, string[]> = {
  timestamp: [
    'timestamp',
    'time',
    'ts',
    'datetime',
    'date',
    'eventtime',
    'logtime',
    'timegenerated',
    'eventtimestamp',
    'created',
    'createdat',
    'occurredat',
    'when',
  ],
  sourceIp: [
    'sourceip',
    'srcip',
    'clientip',
    'remoteaddr',
    'remoteip',
    'sourceaddress',
    'clientaddress',
    'ipaddress',
    'sourceipaddress',
    'callerip',
    'srcaddr',
    'remotehost',
    'rhost',
    'cip',
    'ip',
    'src',
  ],
  username: [
    'username',
    'user',
    'userid',
    'account',
    'accountname',
    'login',
    'principal',
    'targetuser',
    'targetusername',
    'subject',
    'actor',
    'email',
    'usr',
  ],
  statusCode: [
    'statuscode',
    'httpstatus',
    'httpstatuscode',
    'responsecode',
    'responsestatus',
    'httpresponsestatuscode',
    'scstatus',
    'status',
    'code',
  ],
  httpMethod: ['method', 'httpmethod', 'requestmethod', 'httprequestmethod', 'csmethod', 'verb'],
  path: [
    'path',
    'urlpath',
    'uri',
    'requesturi',
    'requestpath',
    'url',
    'urloriginal',
    'csuristem',
    'endpoint',
    'route',
    'request',
  ],
  userAgent: ['useragent', 'httpuseragent', 'useragentoriginal', 'ua', 'agent', 'csuseragent'],
  outcome: [
    'outcome',
    'eventoutcome',
    'result',
    'authresult',
    'loginresult',
    'authstatus',
    'success',
    'status',
  ],
  action: ['action', 'eventaction', 'activity', 'operation'],
  eventType: [
    'eventtype',
    'event',
    'type',
    'eventname',
    'eventcategory',
    'category',
    'logtype',
    'eventid',
  ],
  host: ['host', 'hostname', 'server', 'computer', 'computername', 'device', 'observer'],
  message: ['message', 'msg', 'description', 'details', 'text', 'log'],
  severity: ['severity', 'level', 'loglevel', 'priority', 'sev'],
};

const SUGGESTION_ORDER: MappableField[] = [
  'timestamp',
  'sourceIp',
  'username',
  'statusCode',
  'httpMethod',
  'path',
  'userAgent',
  'outcome',
  'action',
  'eventType',
  'host',
  'message',
  'severity',
];

const majority = (values: FieldValue[], test: (v: FieldValue) => boolean): boolean => {
  if (values.length === 0) return true;
  return values.filter(test).length / values.length >= 0.5;
};

const isStatusCode = (v: FieldValue): boolean => {
  const n = Number(v);
  return Number.isInteger(n) && n >= 100 && n <= 599;
};

const VALUE_CHECKS: Partial<Record<MappableField, (values: FieldValue[]) => boolean>> = {
  timestamp: (vs) =>
    majority(
      vs,
      (v) => parseFlexibleTimestamp(v, { assumedYear: 2000, sourceOffsetMinutes: 0 }).ok,
    ),
  sourceIp: (vs) => majority(vs, (v) => normalizeIp(String(v)) !== undefined),
  statusCode: (vs) => majority(vs, isStatusCode),
  outcome: (vs) => majority(vs, (v) => normalizeOutcome(v) !== undefined),
  httpMethod: (vs) => majority(vs, (v) => /^[A-Z]{3,10}$/.test(String(v))),
};

/**
 * Suggest a field mapping from discovered keys and example values. Keys are
 * matched on their normalized full path and last segment; candidate keys whose
 * example values do not look right for the field (e.g. a non-numeric "status"
 * for HTTP status codes) are skipped.
 */
export function suggestMapping(
  keys: string[],
  examplesFor: (key: string) => FieldValue[],
): FieldMapping {
  const used = new Set<string>();
  const mapping: FieldMapping = {};
  for (const field of SUGGESTION_ORDER) {
    const synonyms = SYNONYMS[field];
    let best: { key: string; rank: number } | undefined;
    for (const key of keys) {
      if (used.has(key)) continue;
      const full = normalizeKey(key);
      const last = normalizeKey(key.split('.').pop() ?? key);
      let rank = synonyms.indexOf(full);
      if (rank === -1) {
        const lastRank = synonyms.indexOf(last);
        rank = lastRank === -1 ? -1 : lastRank + 0.5;
      }
      if (rank === -1) continue;
      const check = VALUE_CHECKS[field];
      if (check && !check(examplesFor(key))) continue;
      if (!best || rank < best.rank) best = { key, rank };
    }
    if (best) {
      mapping[field] = best.key;
      used.add(best.key);
    }
  }
  return mapping;
}

const METHOD_RE = /^[A-Za-z][A-Za-z0-9_-]{0,31}$/;

function splitUrl(value: string): { path: string; query?: string } {
  let target = value;
  const absolute = /^[a-z][a-z0-9+.-]*:\/\/[^/?#]*/i.exec(target);
  if (absolute) target = target.slice(absolute[0].length) || '/';
  const hash = target.indexOf('#');
  if (hash !== -1) target = target.slice(0, hash);
  const q = target.indexOf('?');
  return q === -1 ? { path: target } : { path: target.slice(0, q), query: target.slice(q + 1) };
}

/**
 * Convert a flattened structured record into an event draft using the
 * analyst-confirmed field mapping. Only the timestamp is treated as critical:
 * a mapped timestamp that is missing or invalid makes the record partial.
 * Invalid values in other mapped fields are also reported as issues; absent
 * optional fields are not.
 */
export function mapStructuredRecord(
  record: FlatRecord,
  mapping: FieldMapping,
  options: TimestampOptions,
): EventDraft {
  const issues: string[] = [];
  const mappedKeys = new Set(Object.values(mapping).filter((k): k is string => Boolean(k)));
  const get = (field: MappableField): FieldValue | undefined => {
    const key = mapping[field];
    return key ? record.get(key) : undefined;
  };
  const text = (field: MappableField, max = 512): string | undefined => {
    const v = get(field);
    return v === undefined ? undefined : cleanField(String(v), max);
  };

  const draft: EventDraft = { category: 'other', action: 'event' };

  if (mapping.timestamp) {
    const v = get('timestamp');
    if (v === undefined || String(v).trim() === '') {
      issues.push(`timestamp field "${truncate(mapping.timestamp, 64)}" is missing`);
    } else {
      draft.timestampRaw = truncate(String(v), 64);
      const r = parseFlexibleTimestamp(v, options);
      if (r.ok) draft.timestamp = r.ms;
      else issues.push(`invalid timestamp: ${r.reason}`);
    }
  }

  const rawIp = text('sourceIp', 255);
  if (rawIp !== undefined) {
    const ip = normalizeIp(rawIp);
    if (ip) draft.sourceIp = ip;
    else issues.push('source IP is not a valid IP address');
  }
  const username = text('username', 128);
  if (username) draft.username = username;
  const host = text('host', 255);
  if (host) draft.host = host;
  const message = text('message', 2048);
  if (message) draft.message = message;
  const severity = text('severity', 32);
  if (severity) draft.sourceSeverity = severity;

  const http: HttpDetails = {};
  const method = text('httpMethod', 32);
  if (method !== undefined) {
    if (METHOD_RE.test(method)) http.method = method.toUpperCase();
    else issues.push('invalid HTTP method');
  }
  const rawPath = text('path', 2048);
  if (rawPath !== undefined) {
    const { path, query } = splitUrl(rawPath);
    http.path = path || '/';
    if (query) http.query = query;
  }
  const status = get('statusCode');
  if (status !== undefined && String(status).trim() !== '') {
    if (isStatusCode(status)) http.status = Number(status);
    else issues.push('invalid HTTP status code');
  }
  const ua = text('userAgent', 1024);
  if (ua) http.userAgent = ua;
  const hasHttp = Object.keys(http).length > 0;

  const eventType = text('eventType', 128);
  const actionText = text('action', 128);
  const descriptive = actionText ?? eventType;
  const explicitOutcome = normalizeOutcome(get('outcome'));

  let category: EventCategory =
    inferCategoryFromText(eventType) ?? inferCategoryFromText(actionText) ?? 'other';
  if (category === 'other') {
    if (hasHttp) category = 'web';
    else if (explicitOutcome) category = 'authentication';
  }
  draft.category = category;
  draft.action = toActionLabel(descriptive ?? (category === 'web' ? 'http_request' : 'event'));

  let outcome: AuthOutcome | undefined = explicitOutcome;
  if (!outcome && (category === 'authentication' || category === 'privilege')) {
    outcome = inferOutcomeFromText(descriptive);
  }
  if (category === 'authentication' || category === 'privilege' || outcome) {
    draft.auth = outcome ? { outcome } : {};
  }
  if (hasHttp) draft.http = http;

  const fields: Array<[string, string]> = [];
  if (eventType && actionText) fields.push(['event_type', eventType]);
  for (const [key, value] of record) {
    if (fields.length >= MAX_EXTRA_FIELDS) break;
    if (mappedKeys.has(key)) continue;
    const v = cleanField(String(value), 256);
    if (v !== undefined) fields.push([truncate(key, 64), v]);
  }
  if (fields.length > 0) draft.fields = fields;
  if (issues.length > 0) draft.issues = issues;
  return draft;
}
