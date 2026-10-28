import { describe, expect, it } from 'vitest';
import {
  classifyAuthMessage,
  parseKeyValues,
} from '../../../src/features/log-ingestion/parsers/linuxAuth';
import { fixture, ingest, utc } from '../../helpers/ingest';

describe('Linux auth parser — fixture', () => {
  const result = ingest(fixture('auth/basic-auth.log'), 'linux-auth');
  const byLine = (line: number) => result.events.filter((e) => e.line === line);

  it('accounts for every line', () => {
    const s = result.stats;
    expect(s.totalLines).toBe(15);
    expect(s.rejectedRecords).toBe(1);
    expect(s.partialRecords).toBe(1);
    expect(s.parsedRecords).toBe(13);
    expect(s.eventsCreated).toBe(16);
    expect(s.expandedRepeats).toBe(2);
    expect(s.blankLines + s.skippedLines).toBe(0);
    expect(s.parsedRecords + s.partialRecords + s.rejectedRecords).toBe(s.totalLines);
  });

  it('parses failed password attempts with source, port and method', () => {
    const [e] = byLine(1);
    expect(e).toMatchObject({
      category: 'authentication',
      action: 'ssh_login_failed',
      username: 'root',
      sourceIp: '203.0.113.50',
      host: 'bastion',
      timestamp: utc(2026, 10, 27, 10, 0, 1),
      status: 'parsed',
      auth: {
        outcome: 'failure',
        method: 'password',
        port: 50122,
        program: 'sshd',
        pid: 2101,
        invalidUser: false,
      },
    });
  });

  it('flags failures against non-existent accounts', () => {
    expect(byLine(2)[0]).toMatchObject({
      username: 'admin',
      auth: { outcome: 'failure', invalidUser: true },
    });
  });

  it('does not count informational records as separate attempts', () => {
    const invalid = byLine(3)[0]!;
    expect(invalid.action).toBe('ssh_invalid_user');
    expect(invalid.auth?.outcome).toBeUndefined();
    const pam = byLine(4)[0]!;
    expect(pam).toMatchObject({
      action: 'pam_auth_failure',
      username: 'root',
      sourceIp: '203.0.113.50',
    });
    expect(pam.auth?.outcome).toBeUndefined();
  });

  it('parses accepted logins and sessions', () => {
    expect(byLine(5)[0]).toMatchObject({
      action: 'ssh_login_success',
      username: 'alice',
      sourceIp: '198.51.100.10',
      auth: { outcome: 'success', method: 'publickey' },
    });
    expect(byLine(6)[0]).toMatchObject({
      category: 'session',
      action: 'session_opened',
      username: 'alice',
    });
    expect(byLine(11)[0]).toMatchObject({
      category: 'session',
      action: 'session_closed',
      username: 'root',
    });
  });

  it('parses sudo commands and sudo authentication failures', () => {
    const sudo = byLine(7)[0]!;
    expect(sudo).toMatchObject({
      category: 'privilege',
      action: 'sudo_command',
      username: 'alice',
      auth: { program: 'sudo', outcome: 'success', targetUser: 'root' },
    });
    expect(sudo.fields).toContainEqual(['command', '/usr/bin/systemctl restart nginx']);
    expect(byLine(12)[0]).toMatchObject({
      action: 'sudo_auth_failure',
      username: 'bob',
      auth: { outcome: 'failure' },
    });
  });

  it('expands "message repeated N times" into N events that share the line', () => {
    const repeated = byLine(8);
    expect(repeated).toHaveLength(3);
    expect(repeated.map((e) => e.repeat)).toEqual([
      { index: 1, of: 3 },
      { index: 2, of: 3 },
      { index: 3, of: 3 },
    ]);
    expect(repeated.every((e) => e.auth?.outcome === 'failure' && e.username === 'root')).toBe(
      true,
    );
  });

  it('parses connection-level records', () => {
    expect(byLine(9)[0]).toMatchObject({
      category: 'connection',
      action: 'ssh_connection_closed_preauth',
      username: 'bob',
    });
    expect(byLine(10)[0]).toMatchObject({
      category: 'connection',
      action: 'ssh_no_identification',
      sourceIp: '192.0.2.99',
    });
  });

  it('rejects lines without a syslog header and keeps a bounded preview', () => {
    expect(result.rejected).toEqual([
      expect.objectContaining({
        line: 13,
        reason: 'unrecognized_format',
        preview: 'this line is not a syslog record',
      }),
    ]);
  });

  it('keeps records with an invalid timestamp as partial events', () => {
    const e = byLine(14)[0]!;
    expect(e.status).toBe('partial');
    expect(e.timestamp).toBeUndefined();
    expect(e.issues?.[0]).toMatch(/invalid timestamp/);
    expect(e).toMatchObject({ action: 'ssh_login_success', username: 'carol' });
    expect(result.stats.eventsWithoutTimestamp).toBe(1);
  });

  it('honours RFC 3339 timestamps with offsets and canonicalizes IPv6', () => {
    expect(byLine(15)[0]).toMatchObject({
      timestamp: utc(2026, 10, 27, 8, 9, 0, 123),
      sourceIp: '2001:db8::25',
      username: 'dave',
    });
  });

  it('reports the year and time-zone assumptions it made', () => {
    const codes = result.stats.warnings.map((w) => w.code);
    expect(codes).toEqual(
      expect.arrayContaining([
        'assumed_year',
        'assumed_zone',
        'expanded_repeats',
        'missing_timestamps',
      ]),
    );
  });
});

describe('Linux auth parser — edge cases', () => {
  it('cannot be tricked into a spoofed source address by a crafted username', () => {
    const line =
      'Oct 27 10:00:00 h sshd[1]: Failed password for invalid user x from 192.0.2.1 port 1 ssh2 from 203.0.113.66 port 2222 ssh2';
    const [e] = ingest(line, 'linux-auth').events;
    expect(e?.sourceIp).toBe('203.0.113.66');
    expect(e?.username).toBe('x from 192.0.2.1 port 1 ssh2');
  });

  it('treats "Failed none" as a probe without an outcome', () => {
    const [e] = ingest(
      'Oct 27 10:00:00 h sshd[1]: Failed none for invalid user test from 192.0.2.1 port 22 ssh2',
      'linux-auth',
    ).events;
    expect(e?.action).toBe('ssh_auth_none');
    expect(e?.auth?.outcome).toBeUndefined();
  });

  it('supports OpenSSH 9.8+ sshd-session program names', () => {
    const [e] = ingest(
      'Oct 27 10:00:00 h sshd-session[77]: Accepted password for erin from 192.0.2.5 port 22 ssh2',
      'linux-auth',
    ).events;
    expect(e?.auth?.outcome).toBe('success');
  });

  it('marks a hostname in place of an IP as partial and keeps the value', () => {
    const [e] = ingest(
      'Oct 27 10:00:00 h sshd[1]: Failed password for root from scanner.example.test port 22 ssh2',
      'linux-auth',
    ).events;
    expect(e?.status).toBe('partial');
    expect(e?.sourceIp).toBeUndefined();
    expect(e?.fields).toContainEqual(['source_host', 'scanner.example.test']);
  });

  it('caps repeat expansion and warns', () => {
    const r = ingest(
      'Oct 27 10:00:00 h sshd[1]: message repeated 50 times: [ Failed password for root from 192.0.2.1 port 22 ssh2]',
      'linux-auth',
      {
        limits: { maxRepeatExpansion: 10 },
      },
    );
    expect(r.events).toHaveLength(10);
    expect(r.events[0]?.repeat).toEqual({ index: 1, of: 50 });
    expect(r.stats.warnings.map((w) => w.code)).toContain('repeat_capped');
  });

  it('rolls the year over at a December → January boundary', () => {
    const r = ingest(
      'Dec 31 23:59:59 h sshd[1]: Server listening on 0.0.0.0 port 22.\nJan  1 00:00:01 h sshd[1]: Received signal 15; terminating.',
      'linux-auth',
      { assumedYear: 2025 },
    );
    expect(r.events.map((e) => e.timestamp)).toEqual([
      utc(2025, 12, 31, 23, 59, 59),
      utc(2026, 1, 1, 0, 0, 1),
    ]);
  });

  it('classifies su, systemd-logind and account management messages', () => {
    expect(classifyAuthMessage('su', 'FAILED SU (to root) mallory on pts/2')).toMatchObject({
      action: 'su_failed',
      username: 'mallory',
      auth: { outcome: 'failure', targetUser: 'root' },
    });
    expect(classifyAuthMessage('su', '(to root) alice on pts/0')).toMatchObject({
      action: 'su_success',
    });
    expect(classifyAuthMessage('systemd-logind', 'New session 42 of user alice.')).toMatchObject({
      action: 'session_new',
      username: 'alice',
    });
    expect(
      classifyAuthMessage(
        'useradd',
        'new user: name=backdoor, UID=1001, GID=1001, home=/home/backdoor',
      ),
    ).toMatchObject({
      category: 'privilege',
      action: 'user_created',
      username: 'backdoor',
    });
    expect(classifyAuthMessage('usermod', "add 'backdoor' to group 'sudo'")).toMatchObject({
      action: 'group_member_added',
    });
    expect(
      classifyAuthMessage(
        'sudo',
        '   eve : user NOT in sudoers ; TTY=pts/3 ; PWD=/tmp ; USER=root ; COMMAND=/bin/sh',
      ),
    ).toMatchObject({
      action: 'sudo_not_permitted',
      auth: { outcome: 'failure' },
    });
    expect(classifyAuthMessage('kernel', 'something happened')).toMatchObject({
      category: 'system',
      action: 'syslog_message',
    });
  });

  it('counts PAM failures from non-SSH services as attempts', () => {
    const c = classifyAuthMessage(
      'sudo',
      'pam_unix(sudo:auth): authentication failure; logname=bob uid=1000 euid=0 tty=/dev/pts/1 ruser=bob rhost=  user=bob',
    );
    expect(c).toMatchObject({
      category: 'privilege',
      action: 'sudo_auth_failure',
      username: 'bob',
      auth: { outcome: 'failure' },
    });
    expect(c.ip).toBeUndefined();
  });

  it('parses key=value pairs, ignoring empty values', () => {
    const kv = parseKeyValues('logname= uid=0 rhost=192.0.2.1  user=root');
    expect([...kv]).toEqual([
      ['uid', '0'],
      ['rhost', '192.0.2.1'],
      ['user', 'root'],
    ]);
  });

  it('parses additional sshd connection messages', () => {
    const lines = [
      'Received disconnect from 192.0.2.1 port 22:11: Bye Bye [preauth]',
      'Unable to negotiate with 192.0.2.1 port 22: no matching key exchange method found.',
      'error: maximum authentication attempts exceeded for root from 192.0.2.1 port 22 ssh2 [preauth]',
      'Disconnecting authenticating user root 192.0.2.1 port 22: Too many authentication failures [preauth]',
      'Disconnected from user alice 192.0.2.1 port 22',
      'Connection closed by 192.0.2.1 port 22 [preauth]',
      'PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.1  user=root',
      'Connection from 192.0.2.1 port 5555 on 10.0.0.1 port 22 rdomain ""',
      'some future sshd message',
    ];
    expect(lines.map((l) => classifyAuthMessage('sshd', l).action)).toEqual([
      'ssh_received_disconnect',
      'ssh_negotiation_failed',
      'ssh_max_auth_exceeded',
      'ssh_too_many_failures',
      'ssh_disconnected',
      'ssh_connection_closed',
      'pam_more_failures',
      'ssh_connection',
      'sshd_message',
    ]);
  });

  it('escapes control and bidi characters in extracted fields', () => {
    const [e] = ingest(
      'Oct 27 10:00:00 h sshd[1]: Failed password for invalid user ad\u202emin\u001b[31m from 192.0.2.1 port 22 ssh2',
      'linux-auth',
    ).events;
    expect(e?.username).toBe('ad\\u202emin\\x1b[31m');
    // The original line is preserved exactly for evidence.
    expect(e?.raw).toContain('\u202e');
  });
});
