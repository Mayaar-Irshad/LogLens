# Detection rule reference

> Generated from `src/features/detection/rules/registry.ts`. Every rule is deterministic and threshold-based; thresholds can be changed in the **Detection rules** page and are validated and clamped to the ranges below.

Severity reflects review priority, not confirmation of an incident. MITRE ATT&CK references describe the pattern a rule looks for; they are not attribution.

| Rule                  | Name                                               | Scope   | Defaults                                                                                          |
| --------------------- | -------------------------------------------------- | ------- | ------------------------------------------------------------------------------------------------- |
| [AUTH-001](#auth-001) | Repeated failed logins from one source IP          | ip      | Failed attempts: 10 events; Time window: 5 min                                                    |
| [AUTH-002](#auth-002) | Repeated failed logins against one account         | user    | Failed attempts: 8 events; Time window: 10 min                                                    |
| [AUTH-003](#auth-003) | Possible password spraying from one source IP      | ip      | Distinct usernames: 5 accounts; Time window: 15 min; Max average attempts per account: 3 attempts |
| [AUTH-004](#auth-004) | Successful login after repeated failures           | ip-user | Prior failures: 3 events; Time window: 30 min                                                     |
| [AUTH-005](#auth-005) | Authentication failures across many accounts       | global  | Distinct usernames: 10 accounts; Time window: 30 min; Distinct source IPs: 2 IPs                  |
| [AUTH-006](#auth-006) | Unusually high login activity                      | global  | Attempts: 100 events; Time window: 5 min                                                          |
| [AUTH-007](#auth-007) | Login attempts for non-existent accounts           | ip      | Distinct invalid usernames: 5 accounts; Time window: 30 min                                       |
| [WEB-001](#web-001)   | Burst of HTTP 4xx responses from one client        | ip      | 4xx responses: 50 events; Time window: 5 min                                                      |
| [WEB-002](#web-002)   | Burst of HTTP 5xx server errors                    | global  | 5xx responses: 20 events; Time window: 5 min                                                      |
| [WEB-003](#web-003)   | Repeated requests to sensitive paths               | ip      | Requests: 5 events; Time window: 10 min                                                           |
| [WEB-004](#web-004)   | Directory or path probing                          | ip      | Distinct missing paths: 20 paths; Time window: 5 min                                              |
| [WEB-005](#web-005)   | Suspicious HTTP method patterns                    | ip      | Requests: 1 events                                                                                |
| [WEB-006](#web-006)   | Excessive request volume from one client           | ip      | Requests: 300 events; Time window: 1 min                                                          |
| [WEB-007](#web-007)   | Repeated requests producing errors                 | ip      | Error responses: 10 events; Time window: 10 min                                                   |
| [WEB-008](#web-008)   | Injection or traversal patterns in requests        | ip      | Matching requests: 1 events                                                                       |
| [WEB-009](#web-009)   | Known scanner or attack-tool user agent            | ip      | Requests: 1 events                                                                                |
| [GEN-001](#gen-001)   | Malformed or incomplete log records                | dataset | Share of affected records: 5 %; Affected records: 10 records                                      |
| [GEN-002](#gen-002)   | Event volume spike compared with baseline          | global  | Bucket size: 5 min; Multiplier: 3 ×; Minimum buckets: 12 buckets; Minimum events: 20 events       |
| [GEN-003](#gen-003)   | Indicator associated with multiple detection rules | dataset | Distinct rules: 2 rules                                                                           |

## AUTH-001

### Repeated failed logins from one source IP

Many failed authentication attempts from a single source address within a short window. This pattern is consistent with password guessing, but also with misconfigured clients.

**Requires:** Authentication events with an outcome, a source IP and a timestamp.

| Parameter       | Default   | Allowed range | Meaning                                                                         |
| --------------- | --------- | ------------- | ------------------------------------------------------------------------------- |
| Failed attempts | 10 events | 2–100000      | Minimum failed attempts from one IP within the window.                          |
| Time window     | 5 min     | 1–1440        | Events must fall within this many minutes of each other to be counted together. |

**Investigation steps**

- Check whether any login from this IP succeeded during or after the burst (see AUTH-004 and the event explorer).
- Review which accounts were targeted; prioritise privileged and real (existing) accounts.
- Confirm whether the address belongs to your organisation, a partner, or a known scanner before blocking.
- Consider rate limiting, fail2ban-style blocking, disabling password authentication, or enforcing MFA.

**Limitations**

- Only events the parser recognized as authentication attempts with an explicit outcome are counted (for example sshd "Failed"/"Accepted" lines). Duplicate PAM records are not counted twice.
- A source IP may represent many users behind NAT, a proxy, a VPN concentrator or a bastion host.
- Severity is raised when the measured value reaches a multiple of the threshold; it reflects priority for review, not confirmation of an incident.

**Likely false positives**

- Automation or scripts using an expired password.
- A user repeatedly mistyping a password.
- Shared egress IPs (corporate NAT, VPN) aggregating many users.

**Related ATT&CK techniques:** T1110.001 (Brute Force: Password Guessing)

## AUTH-002

### Repeated failed logins against one account

Many failed authentication attempts against a single username within a short window, from one or more source addresses.

**Requires:** Authentication events with an outcome, a username and a timestamp.

| Parameter       | Default  | Allowed range | Meaning                                                                         |
| --------------- | -------- | ------------- | ------------------------------------------------------------------------------- |
| Failed attempts | 8 events | 2–100000      | Minimum failed attempts against one account within the window.                  |
| Time window     | 10 min   | 1–1440        | Events must fall within this many minutes of each other to be counted together. |

**Investigation steps**

- Confirm with the account owner whether they were attempting to log in.
- Check for a later successful login for this account (AUTH-004) and review activity after it.
- If the attempts come from many IPs, consider a distributed guessing campaign and enable account lockout or MFA.
- Check whether the account is privileged or a service account with a stale credential.

**Limitations**

- Only events the parser recognized as authentication attempts with an explicit outcome are counted (for example sshd "Failed"/"Accepted" lines). Duplicate PAM records are not counted twice.
- A source IP may represent many users behind NAT, a proxy, a VPN concentrator or a bastion host.
- Severity is raised when the measured value reaches a multiple of the threshold; it reflects priority for review, not confirmation of an incident.
- Attempts against accounts that do not exist on the host are lower risk; see the evidence for whether the account was reported as invalid.

**Likely false positives**

- Service accounts or cron jobs using an outdated password.
- Users with a cached old password on a mobile device or mail client.

**Related ATT&CK techniques:** T1110.001 (Brute Force: Password Guessing)

## AUTH-003

### Possible password spraying from one source IP

One source address fails to authenticate as many different usernames within a window, with few attempts per account. Password spraying tries a small number of common passwords across many accounts to avoid lockouts.

**Requires:** Authentication events with an outcome, source IP, username and timestamp.

| Parameter                        | Default    | Allowed range | Meaning                                                                                   |
| -------------------------------- | ---------- | ------------- | ----------------------------------------------------------------------------------------- |
| Distinct usernames               | 5 accounts | 2–10000       | Minimum distinct usernames with failures from one IP within the window.                   |
| Time window                      | 15 min     | 1–1440        | Events must fall within this many minutes of each other to be counted together.           |
| Max average attempts per account | 3 attempts | 1–1000        | Spraying uses few attempts per account. Episodes above this average are left to AUTH-001. |

**Investigation steps**

- Check whether any of the targeted accounts later logged in successfully, from this or any IP.
- Compare the targeted usernames with your real account list; real names indicate prior reconnaissance.
- Enforce MFA and check password policy for the targeted accounts.

**Limitations**

- Only events the parser recognized as authentication attempts with an explicit outcome are counted (for example sshd "Failed"/"Accepted" lines). Duplicate PAM records are not counted twice.
- A source IP may represent many users behind NAT, a proxy, a VPN concentrator or a bastion host.
- Severity is raised when the measured value reaches a multiple of the threshold; it reflects priority for review, not confirmation of an incident.
- Slow sprays spread over hours or days will not be detected with short windows; increase the window to look for them.

**Likely false positives**

- A shared jump host or NAT gateway where several users mistype passwords.
- Vulnerability scanners or penetration tests that are authorised.

**Related ATT&CK techniques:** T1110.003 (Brute Force: Password Spraying)

## AUTH-004

### Successful login after repeated failures

A successful authentication preceded by several failures from the same source IP or against the same account. This can indicate a guessed password, or simply a user who eventually typed it correctly.

**Requires:** Authentication events with success and failure outcomes, and timestamps.

| Parameter      | Default  | Allowed range | Meaning                                                                         |
| -------------- | -------- | ------------- | ------------------------------------------------------------------------------- |
| Prior failures | 3 events | 1–10000       | Minimum failures before the success within the look-back window.                |
| Time window    | 30 min   | 1–1440        | Events must fall within this many minutes of each other to be counted together. |

**Investigation steps**

- Treat as a priority lead: contact the account owner to confirm the login was legitimate.
- Review all activity in the session that followed (commands, sudo use, file changes, new keys).
- If not legitimate: disable the account, rotate credentials and keys, and look for persistence (authorized_keys, cron, new users).
- Check whether the same IP authenticated to other hosts.

**Limitations**

- Correlation is by shared source IP or shared username only; the logs cannot prove the same person made both attempts.
- Successful public-key logins after password failures may be unrelated (for example a user falling back to a key).
- Only events the parser recognized as authentication attempts with an explicit outcome are counted (for example sshd "Failed"/"Accepted" lines). Duplicate PAM records are not counted twice.
- A source IP may represent many users behind NAT, a proxy, a VPN concentrator or a bastion host.
- Severity is raised when the measured value reaches a multiple of the threshold; it reflects priority for review, not confirmation of an incident.

**Likely false positives**

- Users who mistype a password a few times before succeeding.
- Password managers or clients retrying stale credentials before using new ones.

**Related ATT&CK techniques:** T1110 (Brute Force), T1078 (Valid Accounts)

## AUTH-005

### Authentication failures across many accounts

Failed logins against many different accounts from several source addresses within a window. Unlike AUTH-003, this looks across all sources, which can reveal distributed guessing.

**Requires:** Authentication events with an outcome, username, source IP and timestamp.

| Parameter           | Default     | Allowed range | Meaning                                                                         |
| ------------------- | ----------- | ------------- | ------------------------------------------------------------------------------- |
| Distinct usernames  | 10 accounts | 2–100000      | Minimum distinct usernames with failures within the window (all sources).       |
| Time window         | 30 min      | 1–1440        | Events must fall within this many minutes of each other to be counted together. |
| Distinct source IPs | 2 IPs       | 1–100000      | Minimum distinct source IPs involved in the episode.                            |

**Investigation steps**

- Review the list of source IPs for shared infrastructure (same network, hosting provider, or user agent).
- Check whether any targeted account authenticated successfully afterwards.
- Consider global rate limiting or temporary restrictions on password authentication.

**Limitations**

- Only events the parser recognized as authentication attempts with an explicit outcome are counted (for example sshd "Failed"/"Accepted" lines). Duplicate PAM records are not counted twice.
- A source IP may represent many users behind NAT, a proxy, a VPN concentrator or a bastion host.
- Severity is raised when the measured value reaches a multiple of the threshold; it reflects priority for review, not confirmation of an incident.
- Busy systems with many legitimate users can exceed the threshold; tune it to your normal failure volume.

**Likely false positives**

- A widespread password expiry or SSO outage causing many users to fail at once.

**Related ATT&CK techniques:** T1110 (Brute Force)

## AUTH-006

### Unusually high login activity

The total number of authentication attempts (successful and failed) within a window exceeds a configured volume.

**Requires:** Authentication events with an outcome and timestamp.

| Parameter   | Default    | Allowed range | Meaning                                                                         |
| ----------- | ---------- | ------------- | ------------------------------------------------------------------------------- |
| Attempts    | 100 events | 2–100000      | Minimum authentication attempts (any outcome, all sources) within the window.   |
| Time window | 5 min      | 1–1440        | Events must fall within this many minutes of each other to be counted together. |

**Investigation steps**

- Compare with normal login volume for the same time of day.
- Break the burst down by source IP and account in the event explorer.
- If failures dominate, review AUTH-001/AUTH-003 detections for the same period.

**Limitations**

- A fixed threshold does not adapt to the size of your environment; tune it to your normal peak volume.
- Severity is raised when the measured value reaches a multiple of the threshold; it reflects priority for review, not confirmation of an incident.

**Likely false positives**

- Start-of-day login peaks, batch jobs, or monitoring that authenticates frequently.

**Related ATT&CK techniques:** T1110 (Brute Force)

## AUTH-007

### Login attempts for non-existent accounts

One source tries many usernames that the service reports as invalid. This is typical of automated scanning with username dictionaries (for example admin, test, oracle).

**Requires:** Authentication events flagged as invalid-user (e.g. sshd "Invalid user"), with source IP and timestamp.

| Parameter                  | Default    | Allowed range | Meaning                                                                         |
| -------------------------- | ---------- | ------------- | ------------------------------------------------------------------------------- |
| Distinct invalid usernames | 5 accounts | 1–10000       | Minimum distinct non-existent usernames tried by one IP within the window.      |
| Time window                | 30 min     | 1–1440        | Events must fall within this many minutes of each other to be counted together. |

**Investigation steps**

- Usually low risk on its own, because the accounts do not exist; check whether the same IP also targeted real accounts.
- Consider blocking or rate limiting the source if it is not expected.

**Limitations**

- Depends on the service reporting invalid users; many structured logs do not include this flag.
- Distinct usernames are counted, so "Invalid user" and "Failed password for invalid user" lines for the same attempt are not double counted.

**Likely false positives**

- Users mistyping their username; misconfigured clients with a wrong default username.

**Related ATT&CK techniques:** T1110 (Brute Force), T1589.003 (Gather Victim Identity Information: Employee Names)

## WEB-001

### Burst of HTTP 4xx responses from one client

A single client receives many client-error responses (400–499) in a short window. Common with content discovery, broken crawlers, or credential guessing against web logins (401/403).

**Requires:** Web requests with status codes, client IPs and timestamps.

| Parameter     | Default   | Allowed range | Meaning                                                                         |
| ------------- | --------- | ------------- | ------------------------------------------------------------------------------- |
| 4xx responses | 50 events | 2–100000      | Minimum 4xx responses to one client within the window.                          |
| Time window   | 5 min     | 1–1440        | Events must fall within this many minutes of each other to be counted together. |

**Investigation steps**

- Break the burst down by status code: 404s suggest path discovery, 401/403s suggest access attempts.
- Review the requested paths for sensitive targets and any 2xx responses from the same client.
- Consider rate limiting or blocking the client if it is not a known crawler or monitor.

**Limitations**

- Access logs record requests and response codes, not application behaviour; a matching request does not mean an exploit succeeded.
- Client addresses can be load balancers or CDNs unless the log records the original client IP.
- Severity is raised when the measured value reaches a multiple of the threshold; it reflects priority for review, not confirmation of an incident.

**Likely false positives**

- Broken links after a deployment
- Misconfigured monitoring or crawlers
- Single-page apps polling a removed API

**Related ATT&CK techniques:** T1595.003 (Active Scanning: Wordlist Scanning)

## WEB-002

### Burst of HTTP 5xx server errors

Many server-error responses (500–599) across all clients within a window. This usually indicates an application or infrastructure problem, but crafted requests can also trigger server errors.

**Requires:** Web requests with status codes and timestamps.

| Parameter     | Default   | Allowed range | Meaning                                                                         |
| ------------- | --------- | ------------- | ------------------------------------------------------------------------------- |
| 5xx responses | 20 events | 2–100000      | Minimum 5xx responses (all clients) within the window.                          |
| Time window   | 5 min     | 1–1440        | Events must fall within this many minutes of each other to be counted together. |

**Investigation steps**

- Correlate with deployments, application error logs and upstream health checks for the same period.
- Check whether the errors are concentrated on one path or one client (see evidence).
- If one client triggers most errors with unusual input, review those requests for injection attempts (WEB-008).

**Limitations**

- Access logs record requests and response codes, not application behaviour; a matching request does not mean an exploit succeeded.
- Client addresses can be load balancers or CDNs unless the log records the original client IP.
- Severity is raised when the measured value reaches a multiple of the threshold; it reflects priority for review, not confirmation of an incident.

**Likely false positives**

- Outages, deployments, overloaded upstreams or database failures.

**Related ATT&CK techniques:** T1190 (Exploit Public-Facing Application)

## WEB-003

### Repeated requests to sensitive paths

A client repeatedly requests administrative, login, or secret-bearing paths (for example /wp-login.php, /admin, /.env, /.git/). A successful (2xx) response to a secret-bearing path may indicate exposed files.

**Requires:** Web requests with paths, client IPs and timestamps.

| Parameter   | Default  | Allowed range | Meaning                                                                         |
| ----------- | -------- | ------------- | ------------------------------------------------------------------------------- |
| Requests    | 5 events | 1–100000      | Minimum sensitive-path requests from one client within the window.              |
| Time window | 10 min   | 1–1440        | Events must fall within this many minutes of each other to be counted together. |

**Investigation steps**

- Check every 2xx response in the evidence: confirm the file or panel should be reachable from this client.
- If a secret-bearing file (.env, .git, backups) returned 2xx, treat its contents as exposed and rotate any credentials it holds.
- Restrict administrative paths by network location or authentication at the proxy.

**Limitations**

- Access logs record requests and response codes, not application behaviour; a matching request does not mean an exploit succeeded.
- Client addresses can be load balancers or CDNs unless the log records the original client IP.
- Severity is raised when the measured value reaches a multiple of the threshold; it reflects priority for review, not confirmation of an incident.
- The sensitive-path list is a fixed, documented set of common targets; application-specific paths are not included.

**Likely false positives**

- Administrators legitimately using admin or login pages
- Uptime monitors checking a login page

**Related ATT&CK techniques:** T1595.003 (Active Scanning: Wordlist Scanning), T1083 (File and Directory Discovery)

## WEB-004

### Directory or path probing

A client requests many distinct paths that do not exist or are forbidden (404/403/410) in a short window. This is characteristic of content-discovery tools working through a wordlist.

**Requires:** Web requests with paths, status codes, client IPs and timestamps.

| Parameter              | Default  | Allowed range | Meaning                                                                         |
| ---------------------- | -------- | ------------- | ------------------------------------------------------------------------------- |
| Distinct missing paths | 20 paths | 2–100000      | Minimum distinct paths answered 403/404/410 for one client within the window.   |
| Time window            | 5 min    | 1–1440        | Events must fall within this many minutes of each other to be counted together. |

**Investigation steps**

- Review the probed paths to understand what the client was looking for (CMS, backups, admin tools).
- Check for any 2xx responses from the same client in the same period; those are the paths it found.
- Block or rate limit the client if it is not an authorised scanner.

**Limitations**

- Access logs record requests and response codes, not application behaviour; a matching request does not mean an exploit succeeded.
- Client addresses can be load balancers or CDNs unless the log records the original client IP.
- Severity is raised when the measured value reaches a multiple of the threshold; it reflects priority for review, not confirmation of an incident.

**Likely false positives**

- Search-engine crawlers following stale links
- Authorised vulnerability scans

**Related ATT&CK techniques:** T1595.003 (Active Scanning: Wordlist Scanning)

## WEB-005

### Suspicious HTTP method patterns

A client uses rarely needed HTTP methods (TRACE, TRACK, CONNECT, DEBUG, WebDAV methods), non-standard method tokens, or sends request lines that are not valid HTTP (for example TLS handshakes to a plain-HTTP port).

**Requires:** Web requests with client IPs. Timestamps are not required.

| Parameter | Default  | Allowed range | Meaning                                                             |
| --------- | -------- | ------------- | ------------------------------------------------------------------- |
| Requests  | 1 events | 1–100000      | Minimum suspicious-method requests from one client (whole dataset). |

**Investigation steps**

- Confirm whether WebDAV or proxying is intentionally enabled on this server.
- Check whether TRACE/TRACK/CONNECT received a 2xx response; disable them if so.
- Malformed request lines are often port scanners or protocol mismatches and are usually low risk.

**Limitations**

- Some applications use WebDAV legitimately; method lists are generic.
- Not windowed: counts suspicious requests across the whole dataset per client.

**Likely false positives**

- WebDAV clients (file sync tools)
- Health checks speaking the wrong protocol
- Corporate proxies issuing CONNECT

**Related ATT&CK techniques:** T1595.002 (Active Scanning: Vulnerability Scanning)

## WEB-006

### Excessive request volume from one client

A single client sends more requests within the window than the configured limit (possible scraping, flooding, or aggressive automation).

**Requires:** Web requests with client IPs and timestamps.

| Parameter   | Default    | Allowed range | Meaning                                                                         |
| ----------- | ---------- | ------------- | ------------------------------------------------------------------------------- |
| Requests    | 300 events | 2–100000      | Minimum requests from one client within the window.                             |
| Time window | 1 min      | 1–60          | Events must fall within this many minutes of each other to be counted together. |

**Investigation steps**

- Check whether the client is a known crawler, monitor, or internal service.
- Review the error ratio and requested paths; scraping and flooding look different.
- Apply per-client rate limits at the proxy or CDN if the volume is unwanted.

**Limitations**

- Access logs record requests and response codes, not application behaviour; a matching request does not mean an exploit succeeded.
- Client addresses can be load balancers or CDNs unless the log records the original client IP.
- Severity is raised when the measured value reaches a multiple of the threshold; it reflects priority for review, not confirmation of an incident.
- Load balancers or CDNs in front of the server can make many users appear as one client.

**Likely false positives**

- Search-engine crawlers
- API clients with legitimate high throughput
- Load tests

**Related ATT&CK techniques:** T1498 (Network Denial of Service)

## WEB-007

### Repeated requests producing errors

The same client repeats the same request (method and path) and keeps receiving errors (status ≥ 400). Repeated POSTs to a login endpoint are counted whatever the status, because many applications (WordPress, for example) answer a failed login with 200.

**Requires:** Web requests with method, path, status code, client IP and timestamp.

| Parameter       | Default   | Allowed range | Meaning                                                                         |
| --------------- | --------- | ------------- | ------------------------------------------------------------------------------- |
| Error responses | 10 events | 2–100000      | Minimum error responses for the same client, method and path within the window. |
| Time window     | 10 min    | 1–1440        | Events must fall within this many minutes of each other to be counted together. |

**Investigation steps**

- For login endpoints: check application logs for the usernames involved and for any later successful login from the client.
- For other paths: the client may be a broken integration retrying; contact the owner if known.

**Limitations**

- Access logs record requests and response codes, not application behaviour; a matching request does not mean an exploit succeeded.
- Client addresses can be load balancers or CDNs unless the log records the original client IP.
- Severity is raised when the measured value reaches a multiple of the threshold; it reflects priority for review, not confirmation of an incident.

**Likely false positives**

- Integrations retrying with an expired token
- Health checks against a broken endpoint

**Related ATT&CK techniques:** T1110 (Brute Force)

## WEB-008

### Injection or traversal patterns in requests

Request paths, query strings, or user agents contain well-known attack signatures: path traversal, sensitive file inclusion, SQL injection, cross-site scripting, command injection, JNDI lookups (Log4Shell) or Shellshock.

**Requires:** Web requests with paths or user agents. Timestamps are not required.

| Parameter         | Default  | Allowed range | Meaning                                                              |
| ----------------- | -------- | ------------- | -------------------------------------------------------------------- |
| Matching requests | 1 events | 1–100000      | Minimum signature-matching requests from one client (whole dataset). |

**Investigation steps**

- Check the response codes: 4xx usually means the request was refused; 2xx or 5xx deserve a closer look in application logs.
- Verify the targeted component is patched against the matched technique (e.g. Log4j for JNDI lookups).
- Search for the same client in other logs (WAF, application, database).

**Limitations**

- Signatures are simple regular expressions over decoded text; encoding tricks can evade them and benign data can match them.
- A match shows intent in the request, not that the application was vulnerable.
- Not windowed: counts matching requests across the whole dataset per client.

**Likely false positives**

- Security scanners run by your own team
- Search queries that contain SQL or HTML words
- Content-management tools that post markup

**Related ATT&CK techniques:** T1190 (Exploit Public-Facing Application), T1595.002 (Active Scanning: Vulnerability Scanning)

## WEB-009

### Known scanner or attack-tool user agent

Requests whose User-Agent names a common scanning or attack tool (sqlmap, Nikto, Nuclei, Gobuster, …) or an internet-measurement scanner. User agents are trivially spoofed, so this is context, not proof.

**Requires:** Web requests with user agents and client IPs. Timestamps are not required.

| Parameter | Default  | Allowed range | Meaning                                                                     |
| --------- | -------- | ------------- | --------------------------------------------------------------------------- |
| Requests  | 1 events | 1–100000      | Minimum requests with a scanner user agent from one client (whole dataset). |

**Investigation steps**

- Check whether the scan was authorised (internal security team, contracted test).
- Review the other detections for the same client to see what the tool found.

**Limitations**

- Attackers can set any user agent, and real tools often impersonate browsers; absence of a match means nothing.

**Likely false positives**

- Authorised vulnerability scans
- Research scanners that announce themselves

**Related ATT&CK techniques:** T1595 (Active Scanning)

## GEN-001

### Malformed or incomplete log records

A notable share of records could not be parsed, or were parsed with missing or invalid critical fields (for example timestamps or addresses). Gaps in log quality limit every other detection.

**Requires:** Parsing statistics (always available).

| Parameter                 | Default    | Allowed range | Meaning                                                     |
| ------------------------- | ---------- | ------------- | ----------------------------------------------------------- |
| Share of affected records | 5 %        | 1–100         | Minimum percentage of records that are rejected or partial. |
| Affected records          | 10 records | 1–1000000     | Minimum number of rejected or partial records.              |

**Investigation steps**

- Confirm the selected format matches the file; a wrong format choice rejects most lines.
- Inspect the rejected-record samples on the data source page for truncation or unexpected content.
- Check log rotation, shipping and storage for truncation or corruption; unexplained gaps can also follow log tampering.

**Limitations**

- Malformed records are usually caused by format mismatches, multi-format files, or truncated writes, not by attacks.

**Likely false positives**

- Files that mix several log formats
- Logs with custom formats or extra fields

**Related ATT&CK techniques:** T1070 (Indicator Removal)

## GEN-002

### Event volume spike compared with baseline

Event volume in a time bucket is far above the typical (median) bucket of the same dataset. The baseline is computed only from the uploaded data.

**Requires:** Timestamped events spanning at least the configured number of buckets.

| Parameter       | Default    | Allowed range | Meaning                                                                            |
| --------------- | ---------- | ------------- | ---------------------------------------------------------------------------------- |
| Bucket size     | 5 min      | 1–1440        | Size of each time bucket.                                                          |
| Multiplier      | 3 ×        | 2–1000        | A bucket is a spike when it has at least this multiple of the median bucket count. |
| Minimum buckets | 12 buckets | 4–10000       | Minimum number of buckets needed before a baseline is computed.                    |
| Minimum events  | 20 events  | 1–1000000     | A spike bucket must also contain at least this many events.                        |

**Investigation steps**

- Break the spike down by category, source IP and action to see what drove it.
- Compare with deployments, backups, or scheduled jobs at the same time.
- Look for related detections in the same time range.

**Limitations**

- The baseline is the median of this dataset only; short or highly irregular logs produce weak baselines.
- Spikes are relative: in a quiet log a modest burst can qualify, in a busy log a large attack may not.

**Likely false positives**

- Scheduled jobs, backups, log rotation catch-up, or daily traffic peaks

## GEN-003

### Indicator associated with multiple detection rules

The same source IP or account is the subject of detections from several independent rules. Converging signals raise investigation priority; they do not establish attribution.

**Requires:** Detections from other rules.

| Parameter      | Default | Allowed range | Meaning                                                                |
| -------------- | ------- | ------------- | ---------------------------------------------------------------------- |
| Distinct rules | 2 rules | 2–20          | Minimum number of different rules that flagged the same IP or account. |

**Investigation steps**

- Start the investigation with this indicator: open each related detection and build a timeline.
- Pivot to the event explorer filtered by this indicator to see all of its activity.
- If a success-after-failure detection is involved, verify the login with the account owner first.

**Limitations**

- Correlation is by exact IP or username match only; related infrastructure (neighbouring IPs, renamed accounts) is not linked.
- Several rules can fire on the same underlying activity (for example 4xx bursts and path probing). Severity is therefore raised only when three independent kinds of signal agree, and to critical only when a strongly linked login follows overlapping brute force.

**Likely false positives**

- Busy shared infrastructure such as proxies or NAT gateways
