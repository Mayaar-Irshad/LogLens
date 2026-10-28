import type { AuthDetails, EventCategory, EventDraft } from '../../../types/events';
import type { TimestampOptions } from '../../../types/ingestion';
import { formatOffset } from '../../../utils/format';
import { cleanField } from '../../../utils/text';
import { normalizeIp } from '../normalization/ip';
import {
  monthFromName,
  parseIsoTimestamp,
  parseSyslogTimestamp,
  SyslogYearTracker,
} from '../normalization/timestamp';
import { WarningCollector, type ParseOutput, type RecordParser } from './types';

/**
 * Parser for Linux authentication logs (/var/log/auth.log, /var/log/secure,
 * `journalctl -o short` / `short-iso` output).
 *
 * Counting semantics, chosen to avoid double counting a single attempt:
 * - sshd "Failed <method> for ..." is a failed attempt; "Accepted ..." a success.
 * - sshd "Failed none ..." is a protocol probe, not a credential check: no outcome.
 * - "Invalid user ..." is informational (the following "Failed password for
 *   invalid user" line is the attempt) and is flagged with `invalidUser`.
 * - pam_unix(sshd:auth) "authentication failure" duplicates the sshd line and
 *   has no outcome. PAM failures from other services (sudo, su, login) do.
 */

const BSD_HEADER = /^([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?)\s+(\S+)\s+(.*)$/;
const ISO_HEADER =
  /^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?)\s+(\S+)\s+(.*)$/;
/** A syslog priority prefix such as "<38>" written by some forwarders. */
const PRI_PREFIX = /^<\d{1,3}>(?:1 )?/;
/** sysklogd, BusyBox and BSD syslog summarize duplicates on a line of their own. */
const LAST_REPEATED = /^last message repeated (\d{1,9}) times?$/;
const PROGRAM = /^([A-Za-z0-9_./@-]{1,64}?)(?:\[(\d{1,10})\])?:\s?(.*)$/;
const REPEATED = /^message repeated (\d{1,9}) times: \[ ?(.*?) ?\]$/;

interface Classified {
  category: EventCategory;
  action: string;
  ip?: string;
  username?: string;
  auth?: AuthDetails;
  fields?: Array<[string, string]>;
}

const SSH_SUFFIX = String.raw`(?: ssh\d)?(?:: .*)?(?: \[preauth\])?$`;
const SSHD = /^sshd(?:-session|-auth)?$/;

type Matcher = (m: RegExpExecArray) => Classified;

const SSHD_MATCHERS: Array<[RegExp, Matcher]> = [
  [
    // Greedy user group: sshd appends the real address last, so a username that
    // itself contains " from 1.2.3.4 port 22" cannot spoof the source address.
    new RegExp(
      String.raw`^Failed (\S+) for (invalid user )?(.*) from (\S+) port (\d+)${SSH_SUFFIX}`,
    ),
    (m) => {
      const method = m[1]!;
      const probe = method === 'none';
      // A rejected key is what an SSH agent holding several keys produces on every login;
      // it is recorded but not counted as a failed credential attempt.
      const keyOffer = method === 'publickey' || method === 'hostbased';
      const counted = !probe && !keyOffer;
      return {
        category: 'authentication',
        action: probe ? 'ssh_auth_none' : keyOffer ? 'ssh_key_rejected' : 'ssh_login_failed',
        username: m[3],
        ip: m[4],
        auth: {
          method,
          invalidUser: m[2] !== undefined,
          port: Number(m[5]),
          ...(counted ? { outcome: 'failure' as const } : {}),
        },
      };
    },
  ],
  [
    new RegExp(String.raw`^Accepted (\S+) for (.*) from (\S+) port (\d+)${SSH_SUFFIX}`),
    (m) => ({
      category: 'authentication',
      action: 'ssh_login_success',
      username: m[2],
      ip: m[3],
      auth: { method: m[1], outcome: 'success', port: Number(m[4]) },
    }),
  ],
  [
    /^Invalid user (.*) from (\S+)(?: port (\d+))?$/,
    (m) => ({
      category: 'authentication',
      action: 'ssh_invalid_user',
      username: m[1],
      ip: m[2],
      auth: { invalidUser: true, ...(m[3] ? { port: Number(m[3]) } : {}) },
    }),
  ],
  [
    new RegExp(
      String.raw`^error: maximum authentication attempts exceeded for (invalid user )?(.*) from (\S+) port (\d+)${SSH_SUFFIX}`,
    ),
    (m) => ({
      category: 'authentication',
      action: 'ssh_max_auth_exceeded',
      username: m[2],
      ip: m[3],
      auth: { invalidUser: m[1] !== undefined, port: Number(m[4]) },
    }),
  ],
  [
    /^Disconnecting (?:(authenticating|invalid) )?user (.*) (\S+) port (\d+): Too many authentication failures(?: \[preauth\])?$/,
    (m) => ({
      category: 'authentication',
      action: 'ssh_too_many_failures',
      username: m[2],
      ip: m[3],
      auth: { invalidUser: m[1] === 'invalid', port: Number(m[4]) },
    }),
  ],
  [
    /^Connection (?:closed|reset) by (authenticating|invalid) user (.*) (\S+) port (\d+)(?: \[preauth\])?$/,
    (m) => ({
      category: 'connection',
      action: 'ssh_connection_closed_preauth',
      username: m[2],
      ip: m[3],
      auth: { invalidUser: m[1] === 'invalid', port: Number(m[4]) },
    }),
  ],
  [
    /^Connection (?:closed|reset) by (\S+) port (\d+)(?: \[preauth\])?$/,
    (m) => ({
      category: 'connection',
      action: 'ssh_connection_closed',
      ip: m[1],
      auth: { port: Number(m[2]) },
    }),
  ],
  [
    /^Disconnected from (?:(authenticating|invalid) )?user (.*) (\S+) port (\d+)(?: \[preauth\])?$/,
    (m) => ({
      category: 'connection',
      action: 'ssh_disconnected',
      username: m[2],
      ip: m[3],
      auth: { invalidUser: m[1] === 'invalid', port: Number(m[4]) },
    }),
  ],
  [
    /^Disconnected from (\S+) port (\d+)(?: \[preauth\])?$/,
    (m) => ({
      category: 'connection',
      action: 'ssh_disconnected',
      ip: m[1],
      auth: { port: Number(m[2]) },
    }),
  ],
  [
    /^Received disconnect from (\S+) port (\d+):(\d+): ?(.*?)(?: \[preauth\])?$/,
    (m) => ({
      category: 'connection',
      action: 'ssh_received_disconnect',
      ip: m[1],
      auth: { port: Number(m[2]) },
      fields: [
        ['disconnect_code', m[3]!],
        ['disconnect_reason', m[4] ?? ''],
      ],
    }),
  ],
  [
    /^Did not receive identification string from (\S+)(?: port (\d+))?$/,
    (m) => ({
      category: 'connection',
      action: 'ssh_no_identification',
      ip: m[1],
      ...(m[2] ? { auth: { port: Number(m[2]) } } : {}),
    }),
  ],
  [
    /^(?:banner exchange: )?Connection from (\S+) port (\d+)(.*)$/,
    (m) => ({
      category: 'connection',
      action: m[3]?.includes('invalid format') ? 'ssh_banner_invalid' : 'ssh_connection',
      ip: m[1],
      auth: { port: Number(m[2]) },
    }),
  ],
  [
    /^Unable to negotiate with (\S+) port (\d+): (.*)$/,
    (m) => ({
      category: 'connection',
      action: 'ssh_negotiation_failed',
      ip: m[1],
      auth: { port: Number(m[2]) },
      fields: [['negotiation_error', m[3]!]],
    }),
  ],
  [
    /^PAM (\d+) more authentication failures?; (.*)$/,
    (m) => {
      const kv = parseKeyValues(m[2]!);
      return {
        category: 'authentication',
        action: 'pam_more_failures',
        ip: kv.get('rhost'),
        username: kv.get('user'),
        fields: [['additional_failures', m[1]!]],
      };
    },
  ],
  [
    /^Server listening on (\S+) port (\d+)/,
    () => ({ category: 'system', action: 'ssh_server_listening' }),
  ],
  [
    /^Received signal \d+; terminating/,
    () => ({ category: 'system', action: 'ssh_server_stopped' }),
  ],
];

/** Parse "key=value key2= key3=value" pairs as used by pam_unix. */
export function parseKeyValues(text: string): Map<string, string> {
  const out = new Map<string, string>();
  const re = /(\w+)=(\S*)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    if (m[2] !== '') out.set(m[1]!, m[2]!);
  }
  return out;
}

function classifyPam(service: string, facility: string, text: string): Classified {
  if (facility === 'auth') {
    const failure = /^authentication failure;\s*(.*)$/.exec(text);
    if (failure) {
      const kv = parseKeyValues(failure[1]!);
      const viaSshd = SSHD.test(service);
      const isPrivilege = /^(?:sudo|su)(?:-|$)/.test(service);
      return {
        category: isPrivilege ? 'privilege' : 'authentication',
        action: viaSshd
          ? 'pam_auth_failure'
          : `${service.replace(/[^a-z0-9]+/gi, '_')}_auth_failure`,
        ip: kv.get('rhost'),
        username: kv.get('user') ?? kv.get('ruser'),
        auth: {
          program: service,
          ...(viaSshd ? {} : { outcome: 'failure' as const }),
        },
        fields: viaSshd
          ? [['note', 'duplicates the sshd record; not counted as a separate attempt']]
          : [],
      };
    }
    if (/^check pass; user unknown/.test(text)) {
      return {
        category: 'authentication',
        action: 'pam_user_unknown',
        auth: { invalidUser: true },
      };
    }
  }
  if (facility === 'session') {
    const opened =
      /^session opened for user (\S+?)(?:\(uid=\d+\))? by (\S*?)(?:\(uid=\d+\))?$/.exec(text);
    if (opened) {
      return {
        category: 'session',
        action: 'session_opened',
        username: opened[1],
        fields: opened[2] ? [['opened_by', opened[2]]] : [],
        auth: { program: service },
      };
    }
    const closed = /^session closed for user (\S+)$/.exec(text);
    if (closed) {
      return {
        category: 'session',
        action: 'session_closed',
        username: closed[1],
        auth: { program: service },
      };
    }
  }
  if (facility === 'password' || facility === 'chauthtok') {
    const changed = /^password changed for (\S+)$/.exec(text);
    if (changed) return { category: 'system', action: 'password_changed', username: changed[1] };
  }
  return { category: facility === 'session' ? 'session' : 'authentication', action: 'pam_message' };
}

function classifySudo(text: string): Classified {
  const m = /^\s*(\S+) : (.*)$/.exec(text);
  if (!m) return { category: 'privilege', action: 'sudo_message' };
  const user = m[1]!;
  const rest = m[2]!;
  const parts = rest.split(' ; ');
  const kv = new Map<string, string>();
  for (const part of parts) {
    const eq = part.indexOf('=');
    if (eq > 0) kv.set(part.slice(0, eq).trim(), part.slice(eq + 1).trim());
  }
  const fields: Array<[string, string]> = [];
  for (const key of ['TTY', 'PWD', 'COMMAND']) {
    const v = kv.get(key);
    if (v) fields.push([key.toLowerCase(), v]);
  }
  let action = 'sudo_command';
  let outcome: 'success' | 'failure' = 'success';
  if (/incorrect password attempts?/.test(rest)) {
    action = 'sudo_auth_failure';
    outcome = 'failure';
  } else if (/NOT in sudoers|command not allowed|a password is required/.test(rest)) {
    action = 'sudo_not_permitted';
    outcome = 'failure';
  }
  return {
    category: 'privilege',
    action,
    username: user,
    auth: { program: 'sudo', outcome, ...(kv.get('USER') ? { targetUser: kv.get('USER') } : {}) },
    fields,
  };
}

function classifySu(text: string): Classified {
  const failed =
    /^FAILED SU \(to (\S+)\) (\S+) on (\S+)$/.exec(text) ??
    /^FAILED su for (\S+) by (\S+)$/.exec(text);
  if (failed) {
    return {
      category: 'privilege',
      action: 'su_failed',
      username: failed[2],
      auth: { program: 'su', outcome: 'failure', targetUser: failed[1] },
    };
  }
  const ok =
    /^\(to (\S+)\) (\S+) on (\S+)$/.exec(text) ?? /^Successful su for (\S+) by (\S+)$/.exec(text);
  if (ok) {
    return {
      category: 'privilege',
      action: 'su_success',
      username: ok[2],
      auth: { program: 'su', outcome: 'success', targetUser: ok[1] },
    };
  }
  return { category: 'privilege', action: 'su_message' };
}

function classifyLogind(text: string): Classified {
  const created = /^New session (\S+) of user (\S+?)\.?$/.exec(text);
  if (created) {
    return {
      category: 'session',
      action: 'session_new',
      username: created[2],
      fields: [['session', created[1]!]],
    };
  }
  if (/^Removed session /.test(text)) return { category: 'session', action: 'session_removed' };
  if (/^Session \S+ logged out/.test(text))
    return { category: 'session', action: 'session_logged_out' };
  return { category: 'system', action: 'logind_message' };
}

function classifyAccountTool(program: string, text: string): Classified | undefined {
  if (program === 'useradd') {
    const m = /^new user: name=([^,]+),/.exec(text);
    if (m) return { category: 'privilege', action: 'user_created', username: m[1] };
  }
  if (program === 'userdel') {
    const m = /^delete user '([^']+)'/.exec(text);
    if (m) return { category: 'privilege', action: 'user_deleted', username: m[1] };
  }
  if (program === 'usermod' || program === 'gpasswd') {
    const m =
      /^add '([^']+)' to (?:shadow )?group '([^']+)'/.exec(text) ??
      /^user (\S+) added by \S+ to group (\S+)/.exec(text);
    if (m) {
      return {
        category: 'privilege',
        action: 'group_member_added',
        username: m[1],
        fields: [['group', m[2]!]],
      };
    }
  }
  return undefined;
}

/** Dropbear (embedded devices and routers) logs addresses as ip:port. */
function classifyDropbear(text: string): Classified | undefined {
  const bad = /^Bad password attempt for '(.*)' from (\S+?):(\d+)$/.exec(text);
  if (bad) {
    return {
      category: 'authentication',
      action: 'ssh_login_failed',
      username: bad[1],
      ip: bad[2],
      auth: { method: 'password', outcome: 'failure', port: Number(bad[3]) },
    };
  }
  const missing = /^Login attempt for nonexistent user(?: '(.*)')? from (\S+?):(\d+)$/.exec(text);
  if (missing) {
    return {
      category: 'authentication',
      action: 'ssh_login_failed',
      ...(missing[1] ? { username: missing[1] } : {}),
      ip: missing[2],
      auth: { outcome: 'failure', invalidUser: true, port: Number(missing[3]) },
    };
  }
  const ok =
    /^(Password|Pubkey) auth succeeded for '(.*?)'(?: with key .*?)? from (\S+?):(\d+)$/.exec(text);
  if (ok) {
    return {
      category: 'authentication',
      action: 'ssh_login_success',
      username: ok[2],
      ip: ok[3],
      auth: {
        method: ok[1] === 'Password' ? 'password' : 'publickey',
        outcome: 'success',
        port: Number(ok[4]),
      },
    };
  }
  return undefined;
}

/** Classify a syslog message by program. Exported for unit tests. */
export function classifyAuthMessage(program: string | undefined, message: string): Classified {
  const pam = /^pam_unix\(([^:)]+):(\w+)\): (.*)$/.exec(message);
  if (pam) return classifyPam(pam[1]!, pam[2]!, pam[3]!);
  if (program && SSHD.test(program)) {
    for (const [re, build] of SSHD_MATCHERS) {
      const m = re.exec(message);
      if (m) return build(m);
    }
    return { category: 'other', action: 'sshd_message' };
  }
  if (program === 'dropbear') {
    const d = classifyDropbear(message);
    if (d) return d;
  }
  if (program === 'sudo') return classifySudo(message);
  if (program === 'su') return classifySu(message);
  if (program === 'systemd-logind') return classifyLogind(message);
  if (program) {
    const account = classifyAccountTool(program, message);
    if (account) return account;
  }
  return { category: 'system', action: 'syslog_message' };
}

function buildDraft(
  classified: Classified,
  base: {
    timestamp?: number;
    timestampRaw: string;
    host: string;
    message: string;
    program?: string;
    pid?: number;
  },
  issues: string[],
): EventDraft {
  const draftIssues = [...issues];
  const draft: EventDraft = {
    category: classified.category,
    action: classified.action,
    timestampRaw: base.timestampRaw,
    message: cleanField(base.message, 2048),
  };
  if (base.timestamp !== undefined) draft.timestamp = base.timestamp;
  const host = cleanField(base.host, 255);
  if (host) draft.host = host;
  const username = cleanField(classified.username, 128);
  if (username) draft.username = username;
  if (classified.ip !== undefined) {
    const ip = normalizeIp(classified.ip);
    if (ip) draft.sourceIp = ip;
    else {
      draftIssues.push('source address is not a valid IP address');
      classified.fields = [
        ...(classified.fields ?? []),
        ['source_host', cleanField(classified.ip, 255) ?? ''],
      ];
    }
  }
  const auth: AuthDetails = { ...(classified.auth ?? {}) };
  if (base.program && !auth.program) auth.program = base.program;
  if (base.pid !== undefined) auth.pid = base.pid;
  if (
    auth.port !== undefined &&
    !(Number.isInteger(auth.port) && auth.port >= 0 && auth.port <= 65535)
  ) {
    delete auth.port;
    draftIssues.push('invalid port');
  }
  if (auth.targetUser !== undefined) {
    const target = cleanField(auth.targetUser, 128);
    if (target) auth.targetUser = target;
    else delete auth.targetUser;
  }
  if (Object.keys(auth).length > 0) draft.auth = auth;
  const fields = (classified.fields ?? [])
    .map(([k, v]) => [k, cleanField(v, 512)] as const)
    .filter((kv): kv is readonly [string, string] => kv[1] !== undefined)
    .map(([k, v]): [string, string] => [k, v]);
  if (fields.length > 0) draft.fields = fields;
  if (draftIssues.length > 0) draft.issues = draftIssues;
  return draft;
}

export function createLinuxAuthParser(
  options: TimestampOptions & { maxRepeatExpansion: number },
): RecordParser {
  const years = new SyslogYearTracker(options.assumedYear);
  const warnings = new WarningCollector();
  let sawBsdTimestamp = false;

  /** The previous record per host, for "last message repeated N times". */
  const lastDraft = new Map<string, EventDraft>();

  const parseLine = (input: string, lineNumber: number): ParseOutput => {
    // journalctl inserts "-- Boot <id> --" and "-- No entries --" separators.
    if (/^-- .* --$/.test(input.trim()))
      return { type: 'skip', line: lineNumber, reason: 'comment' };
    const line = input.replace(PRI_PREFIX, '');
    const iso = ISO_HEADER.exec(line);
    const bsd = iso ? null : BSD_HEADER.exec(line);
    const header = iso ?? bsd;
    if (!header) {
      return {
        type: 'reject',
        line: lineNumber,
        raw: input,
        reason: 'unrecognized_format',
        detail: 'line does not start with a syslog timestamp and hostname',
      };
    }
    const timestampRaw = header[1]!;
    const issues: string[] = [];
    let timestamp: number | undefined;
    if (iso) {
      const r = parseIsoTimestamp(timestampRaw, options.sourceOffsetMinutes);
      if (r.ok) timestamp = r.ms;
      else issues.push(`invalid timestamp: ${r.reason}`);
    } else {
      sawBsdTimestamp = true;
      const monthName = /^([A-Za-z]{3})/.exec(timestampRaw)?.[1] ?? '';
      const month = monthFromName(monthName);
      const year = month === undefined ? options.assumedYear : years.yearFor(month);
      const r = parseSyslogTimestamp(timestampRaw, year, options.sourceOffsetMinutes);
      if (r.ok) timestamp = r.ms;
      else issues.push(`invalid timestamp: ${r.reason}`);
    }

    const host = header[2]!;
    let rest = header[3]!;
    const prog = PROGRAM.exec(rest);
    let program: string | undefined;
    let pid: number | undefined;
    if (prog) {
      program = prog[1];
      pid = prog[2] === undefined ? undefined : Number(prog[2]);
      rest = prog[3]!;
    }

    let repeatCount = 1;
    const repeated = REPEATED.exec(rest);
    if (repeated) {
      repeatCount = Number(repeated[1]);
      rest = repeated[2]!;
    }
    const lastRepeated = program === undefined ? LAST_REPEATED.exec(rest) : null;
    const previous = lastRepeated ? lastDraft.get(header[2]!) : undefined;
    if (lastRepeated && previous) {
      // The repeats happened after the previous record; this line's time is when they were summarized.
      const count = Math.min(Number(lastRepeated[1]), options.maxRepeatExpansion);
      if (count < Number(lastRepeated[1])) {
        warnings.add(
          'repeat_capped',
          `Some "message repeated N times" lines exceeded the expansion limit of ${options.maxRepeatExpansion}; only that many events were created per line.`,
        );
      }
      const drafts: EventDraft[] = Array.from({ length: count }, (_, i) => ({
        ...previous,
        timestampRaw,
        ...(timestamp !== undefined ? { timestamp } : {}),
        ...(issues.length > 0 ? { issues } : {}),
        repeat: { index: i + 1, of: Number(lastRepeated[1]) },
      }));
      return { type: 'event', line: lineNumber, raw: input, drafts };
    }
    const classified = classifyAuthMessage(program, rest);
    const base = {
      timestampRaw,
      host,
      message: rest,
      ...(timestamp !== undefined ? { timestamp } : {}),
      ...(program !== undefined ? { program } : {}),
      ...(pid !== undefined ? { pid } : {}),
    };
    const draft = buildDraft(classified, base, issues);
    lastDraft.set(host, draft);
    if (repeatCount <= 1) return { type: 'event', line: lineNumber, raw: input, drafts: [draft] };

    const expanded = Math.min(repeatCount, options.maxRepeatExpansion);
    if (expanded < repeatCount) {
      warnings.add(
        'repeat_capped',
        `Some "message repeated N times" lines exceeded the expansion limit of ${options.maxRepeatExpansion}; only that many events were created per line.`,
      );
    }
    const drafts: EventDraft[] = [];
    for (let i = 0; i < expanded; i++) {
      drafts.push({ ...draft, repeat: { index: i + 1, of: repeatCount } });
    }
    return { type: 'event', line: lineNumber, raw: input, drafts };
  };

  return {
    format: 'linux-auth',
    push: (line, lineNumber) => [parseLine(line, lineNumber)],
    finish: () => [],
    isBuffering: () => false,
    warnings: () => {
      const list = warnings.list();
      if (sawBsdTimestamp) {
        list.push({
          code: 'assumed_year',
          message:
            `Syslog timestamps do not include a year. ${options.assumedYear} was assumed for the first record` +
            (years.rollovers > 0 ? `, with ${years.rollovers} year rollover(s) detected.` : '.'),
          count: 1,
        });
        list.push({
          code: 'assumed_zone',
          message: `Syslog timestamps do not include a time zone; they were interpreted as ${formatOffset(options.sourceOffsetMinutes)}.`,
          count: 1,
        });
      }
      return list;
    },
  };
}
