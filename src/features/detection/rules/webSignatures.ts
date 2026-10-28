/**
 * Transparent signature lists used by web rules. They are deliberately small
 * and readable: each match is shown to the analyst together with the pattern
 * label so the reason for a detection is never opaque.
 */

/** Percent-decode up to twice (to expose double encoding), never throwing. */
export function safeDecode(value: string): string {
  let out = value.replace(/\+/g, ' ');
  for (let i = 0; i < 2; i++) {
    try {
      const next = decodeURIComponent(out);
      if (next === out) break;
      out = next;
    } catch {
      out = out.replace(/%([0-9a-f]{2})/gi, (_, hex: string) =>
        String.fromCharCode(parseInt(hex, 16)),
      );
      break;
    }
  }
  return out;
}

export type SensitiveKind = 'admin' | 'auth' | 'secret';

export interface SensitivePath {
  label: string;
  kind: SensitiveKind;
  pattern: RegExp;
}

export const SENSITIVE_PATHS: SensitivePath[] = [
  {
    label: 'WordPress login',
    kind: 'auth',
    pattern: /^\/wp-login\.php$/i,
  },
  {
    label: 'WordPress admin',
    kind: 'admin',
    pattern: /^\/wp-admin(?:\/|$)/i,
  },
  {
    label: 'Admin panel',
    kind: 'admin',
    pattern:
      /^\/(?:admin|administrator|webadmin|admin\.php|cpanel|manager\/html|admin-console)(?:\/|$|\.)/i,
  },
  {
    label: 'phpMyAdmin',
    kind: 'admin',
    pattern: /^\/(?:phpmyadmin|pma|myadmin|mysqladmin)(?:\/|$)/i,
  },
  {
    label: 'Login endpoint',
    kind: 'auth',
    pattern:
      /^\/(?:login|signin|sign-in|logon|user\/login|users\/sign_in|auth\/login|api\/(?:v\d+\/)?(?:login|auth|session|token))(?:\/|$|\.)/i,
  },
  { label: 'XML-RPC', kind: 'auth', pattern: /^\/xmlrpc\.php$/i },
  { label: 'OAuth token endpoint', kind: 'auth', pattern: /^\/oauth2?\/token(?:\/|$)/i },
  { label: 'Environment file', kind: 'secret', pattern: /(?:^|\/)\.env(?:\.[\w-]+)?$/i },
  {
    label: 'Version-control metadata',
    kind: 'secret',
    pattern: /(?:^|\/)\.(?:git|svn|hg)(?:\/|$)/i,
  },
  {
    label: 'Web server access-control file',
    kind: 'secret',
    pattern: /(?:^|\/)\.ht(?:access|passwd)$/i,
  },
  {
    label: 'Application config file',
    kind: 'secret',
    // Generic names such as config.json only count at the site root: /assets/config.json is a
    // normal front-end file.
    pattern:
      /(?:(?:^|\/)(?:wp-config\.php|config\.php|configuration\.php|web\.config)|^\/(?:settings\.py|config\.(?:json|ya?ml)))(?:\.bak|~)?$/i,
  },
  {
    label: 'Cloud / SSH credentials',
    kind: 'secret',
    pattern: /(?:^|\/)(?:\.aws\/credentials|\.ssh\/|id_rsa|id_ed25519)/i,
  },
  {
    label: 'Backup or dump file',
    kind: 'secret',
    pattern: /\.(?:bak|old|orig|sql|sql\.gz|tar\.gz|tgz|dump)$/i,
  },
  {
    // Endpoints that expose configuration or memory when reachable.
    label: 'Diagnostic endpoint exposing configuration',
    kind: 'secret',
    pattern:
      /^\/(?:actuator\/(?:env|heapdump|configprops|mappings|beans)|_profiler|phpinfo\.php)(?:\/|$)/i,
  },
  {
    // Health and status pages are routinely polled by monitoring; access is worth knowing,
    // not a sign that a secret was served.
    label: 'Status or debug endpoint',
    kind: 'admin',
    pattern: /^\/(?:server-status|server-info|actuator(?:\/|$)|debug(?:\/|$)|console(?:\/|$))/i,
  },
  { label: 'macOS metadata file', kind: 'secret', pattern: /(?:^|\/)\.DS_Store$/i },
];

export function matchSensitivePath(path: string): SensitivePath | undefined {
  const decoded = safeDecode(path);
  return SENSITIVE_PATHS.find((s) => s.pattern.test(decoded));
}

export interface RequestSignature {
  id: string;
  label: string;
  pattern: RegExp;
  /** Also check the user agent (e.g. Log4Shell, Shellshock). */
  checkUserAgent?: boolean;
  /** Indicates high-impact exploitation attempts. */
  critical?: boolean;
}

export const REQUEST_SIGNATURES: RequestSignature[] = [
  { id: 'traversal', label: 'Path traversal', pattern: /(?:\.\.[/\\]|[/\\]\.\.(?:$|[/\\]))/ },
  {
    id: 'lfi',
    label: 'Sensitive file inclusion',
    pattern: /(?:\/etc\/(?:passwd|shadow|hosts)|\/proc\/self\/|win\.ini|boot\.ini|c:\\windows)/i,
  },
  {
    id: 'sqli',
    label: 'SQL injection',
    pattern:
      /(?:\bunion\b[\s\S]{0,40}\bselect\b|'\s*or\s*'?\d*'?\s*=\s*'?\d*|\bor\s+\d+\s*=\s*\d+|\bsleep\s*\(\s*\d+\s*\)|\bbenchmark\s*\(|information_schema|\bwaitfor\s+delay\b)/i,
  },
  {
    id: 'xss',
    label: 'Cross-site scripting',
    pattern:
      /(?:<\s*script|javascript:|\bon(?:error|load|mouseover)\s*=\s*[^&\s]|<\s*svg[\s/]|<\s*img[^>]{1,200}src)/i,
  },
  {
    id: 'cmdi',
    label: 'Command injection',
    pattern: /(?:[;|`]|\$\(|&&)\s*(?:cat|wget|curl|bash|sh|nc|ncat|id|whoami|uname|chmod)\b/i,
  },
  {
    id: 'log4shell',
    label: 'JNDI lookup (Log4Shell)',
    // Tested on text whose nested lookups (${lower:j}, ${::-n}, ${env:X:-d}) are already resolved.
    pattern: /\$\{\s*jndi\s*:/i,
    checkUserAgent: true,
    critical: true,
  },
  {
    id: 'shellshock',
    label: 'Shellshock',
    pattern: /\(\s*\)\s*\{\s*:\s*;\s*\}/,
    checkUserAgent: true,
    critical: true,
  },
  {
    id: 'php-wrapper',
    label: 'PHP wrapper / config injection',
    pattern:
      /(?:php:\/\/(?:input|filter)|data:\/\/|expect:\/\/|allow_url_include|auto_prepend_file)/i,
  },
];

export interface SignatureMatch {
  signature: RequestSignature;
  where: 'request' | 'user-agent' | 'referrer';
}

/**
 * Resolve the Log4j lookup obfuscations attackers use to hide "jndi":
 * ${lower:j}, ${upper:J}, ${::-n}, ${env:NaN:-d}, ${date:'i'}. Applied a few
 * times so nested forms collapse. Bounded so hostile input stays linear.
 */
export function resolveLookups(text: string): string {
  let out = text;
  for (let i = 0; i < 4; i++) {
    const next = out
      .replace(/\$\{(?:lower|upper):([^${}]{0,16})\}/gi, '$1')
      .replace(/\$\{[^${}]{0,64}:-([^${}]{0,16})\}/g, '$1')
      .replace(/\$\{date:'([^'{}]{0,16})'\}/gi, '$1');
    if (next === out) break;
    out = next;
  }
  return out;
}

export function matchRequestSignatures(
  target: string,
  userAgent: string | undefined,
  referrer?: string,
): SignatureMatch[] {
  const decoded = safeDecode(target);
  const resolved = resolveLookups(decoded);
  const out: SignatureMatch[] = [];
  for (const sig of REQUEST_SIGNATURES) {
    const text = sig.id === 'log4shell' ? resolved : decoded;
    if (sig.pattern.test(text)) out.push({ signature: sig, where: 'request' });
    else if (sig.checkUserAgent && userAgent && sig.pattern.test(resolveLookups(userAgent)))
      out.push({ signature: sig, where: 'user-agent' });
    else if (
      sig.checkUserAgent &&
      referrer &&
      sig.pattern.test(resolveLookups(safeDecode(referrer)))
    )
      out.push({ signature: sig, where: 'referrer' });
  }
  return out;
}

export const STANDARD_METHODS = new Set([
  'GET',
  'HEAD',
  'POST',
  'PUT',
  'DELETE',
  'PATCH',
  'OPTIONS',
]);

export const UNUSUAL_METHODS = new Set([
  'TRACE',
  'TRACK',
  'CONNECT',
  'DEBUG',
  'PROPFIND',
  'PROPPATCH',
  'MKCOL',
  'COPY',
  'MOVE',
  'LOCK',
  'UNLOCK',
  'SEARCH',
]);

export interface ScannerAgent {
  label: string;
  pattern: RegExp;
  /** Research / internet-measurement scanners that announce themselves. */
  research?: boolean;
}

export const SCANNER_AGENTS: ScannerAgent[] = [
  { label: 'sqlmap', pattern: /sqlmap/i },
  { label: 'Nikto', pattern: /nikto/i },
  { label: 'Nmap scripting engine', pattern: /nmap/i },
  { label: 'masscan', pattern: /masscan/i },
  { label: 'zgrab', pattern: /zgrab/i },
  { label: 'Gobuster', pattern: /gobuster/i },
  { label: 'DirBuster / dirb', pattern: /dirbuster|\bdirb\b/i },
  { label: 'ffuf / wfuzz / feroxbuster', pattern: /\bffuf\b|wfuzz|feroxbuster/i },
  { label: 'Nuclei', pattern: /nuclei/i },
  { label: 'WPScan', pattern: /wpscan/i },
  {
    label: 'Commercial vulnerability scanner',
    pattern: /acunetix|nessus|openvas|qualys|netsparker|w3af/i,
  },
  { label: 'Hydra', pattern: /hydra/i },
  {
    label: 'Internet measurement scanner',
    pattern: /censys|shodan|internet-measurement|expanseinc|paloaltonetworks/i,
    research: true,
  },
];

export function matchScannerAgent(userAgent: string | undefined): ScannerAgent | undefined {
  if (!userAgent) return undefined;
  return SCANNER_AGENTS.find((s) => s.pattern.test(userAgent));
}
