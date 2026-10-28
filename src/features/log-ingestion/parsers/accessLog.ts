import type { EventDraft, HttpDetails } from '../../../types/events';
import type { TimestampOptions } from '../../../types/ingestion';
import { cleanField } from '../../../utils/text';
import { normalizeIp } from '../normalization/ip';
import { parseClfTimestamp } from '../normalization/timestamp';
import { WarningCollector, type ParseOutput, type RecordParser } from './types';

/**
 * Parser for Apache and Nginx access logs in Common Log Format and Combined
 * Log Format (Nginx's default `combined` format is identical to Apache's):
 *
 *   %h %l %u %t "%r" %>s %b ["%{Referer}i" "%{User-Agent}i"] [extra...]
 *
 * An optional Apache vhost prefix ("%v:%p ") and arbitrary trailing fields
 * (for example Nginx's "$http_x_forwarded_for" or "$request_time") are accepted.
 */

const CLF =
  /^(?:(\S+:\d+) )?(\S+) (\S+) (\S+) \[([^\]]{1,64})\] "((?:[^"\\]|\\.)*)" (\d{3}|-) (\d+|-)(.*)$/;
// The target may contain spaces when a client sends them unencoded (attack payloads often
// do); the protocol, if present, is the last token.
const REQUEST = /^([A-Za-z][A-Za-z0-9_-]{0,31}) (\S(?:.{0,8190}?\S)?)(?: (HTTP\/\d(?:\.\d)?))?$/;

/** Decode the escapes both servers use for quotes and backslashes; leave \xHH visible. */
export function unescapeLogString(value: string): string {
  return value.replace(/\\(["\\])/g, '$1');
}

/** Tokenize trailing fields: quoted strings and bare tokens. */
export function tokenizeTrailing(text: string): Array<{ quoted: boolean; value: string }> {
  const tokens: Array<{ quoted: boolean; value: string }> = [];
  const re = /"((?:[^"\\]|\\.)*)"|(\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null && tokens.length < 16) {
    if (m[1] !== undefined) tokens.push({ quoted: true, value: unescapeLogString(m[1]) });
    else tokens.push({ quoted: false, value: m[2]! });
  }
  return tokens;
}

export interface ParsedRequestLine {
  method?: string;
  path?: string;
  query?: string;
  protocol?: string;
  malformed: boolean;
}

export function parseRequestLine(request: string): ParsedRequestLine {
  if (request === '-' || request === '') return { malformed: false };
  const m = REQUEST.exec(request);
  if (!m) return { malformed: true };
  const target = m[2]!;
  const q = target.indexOf('?');
  const result: ParsedRequestLine = {
    method: m[1]!,
    path: q === -1 ? target : target.slice(0, q),
    malformed: false,
  };
  if (q !== -1) result.query = target.slice(q + 1);
  if (m[3]) result.protocol = m[3];
  return result;
}

export function createAccessLogParser(
  format: 'apache' | 'nginx',
  options: TimestampOptions,
): RecordParser {
  const warnings = new WarningCollector();

  const parseLine = (line: string, lineNumber: number): ParseOutput => {
    const m = CLF.exec(line);
    if (!m) {
      return {
        type: 'reject',
        line: lineNumber,
        raw: line,
        reason: 'unrecognized_format',
        detail: 'line does not match Common or Combined Log Format',
      };
    }
    const [, vhost, client, , authUser, time, rawRequest, status, bytes, trailing] = m;
    const issues: string[] = [];
    const draft: EventDraft = { category: 'web', action: 'http_request', timestampRaw: time };
    const fields: Array<[string, string]> = [];

    const ts = parseClfTimestamp(time!, options.sourceOffsetMinutes);
    if (ts.ok) draft.timestamp = ts.ms;
    else issues.push(`invalid timestamp: ${ts.reason}`);

    const ip = normalizeIp(client);
    if (ip) draft.sourceIp = ip;
    else {
      issues.push('client address is not a valid IP address');
      fields.push(['client_host', cleanField(client, 255) ?? '']);
    }

    const user = cleanField(authUser, 128);
    if (user) draft.username = user;
    if (vhost) fields.push(['vhost', cleanField(vhost, 255) ?? '']);

    const request = unescapeLogString(rawRequest!);
    const parsed = parseRequestLine(request);
    const http: HttpDetails = {};
    if (parsed.malformed) {
      issues.push('malformed request line');
      fields.push(['request', cleanField(request, 1024) ?? '']);
    } else {
      if (parsed.method) http.method = parsed.method;
      const path = cleanField(parsed.path, 2048);
      if (path) http.path = path;
      const query = cleanField(parsed.query, 2048);
      if (query) http.query = query;
      if (parsed.protocol) http.protocol = parsed.protocol;
      if (request === '-') fields.push(['request', '-']);
    }

    if (status === '-') issues.push('missing status code');
    else {
      const code = Number(status);
      if (code >= 100 && code <= 599) http.status = code;
      else issues.push(`invalid status code ${status}`);
    }
    if (bytes !== '-') http.bytes = Number(bytes);

    const tokens = tokenizeTrailing(trailing ?? '');
    if (tokens.length >= 2 && tokens[0]!.quoted && tokens[1]!.quoted) {
      const referrer = cleanField(tokens[0]!.value, 2048);
      if (referrer) http.referrer = referrer;
      const ua = cleanField(tokens[1]!.value, 1024);
      if (ua) http.userAgent = ua;
      const extra = tokens.slice(2);
      if (extra.length > 0) {
        warnings.add(
          'extra_fields',
          'Some lines contain fields after the user agent; they are kept as additional fields.',
        );
        extra.forEach((t, i) => {
          const v = cleanField(t.value, 512);
          if (v) fields.push([`extra_${i + 1}`, v]);
        });
      }
    } else if (tokens.length > 0) {
      const v = cleanField(tokens.map((t) => t.value).join(' '), 512);
      if (v) fields.push(['trailing', v]);
    }

    draft.http = http;
    const cleanFields = fields.filter(([, v]) => v !== '');
    if (cleanFields.length > 0) draft.fields = cleanFields;
    if (issues.length > 0) draft.issues = issues;
    return { type: 'event', line: lineNumber, raw: line, drafts: [draft] };
  };

  return {
    format,
    push: (line, lineNumber) => [parseLine(line, lineNumber)],
    finish: () => [],
    isBuffering: () => false,
    warnings: () => warnings.list(),
  };
}
