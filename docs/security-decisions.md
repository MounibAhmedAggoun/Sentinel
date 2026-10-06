# Security Decisions

A running log. Add an entry whenever a security-relevant choice is made.

## Template

- **Date:**
- **Decision:**
- **Why:**
- **Alternatives considered:**

## Target validation and net-guard (Phase 1)

- **Decision:** Every target passes two checks before any network activity.
  First, a shape check (zod): it must be a plain hostname or IP, so URLs,
  paths, ports, shell characters, and numeric IP forms like `2130706433` are
  rejected. Second, net-guard resolves the name and rejects the target if
  any resolved IP is private, loopback, link-local, or reserved (IPv4 and
  IPv6, including IPv4-mapped IPv6).
- **Why:** The scanner makes outbound connections, so it could be abused to
  probe internal networks or cloud metadata (SSRF).
- **`--allow-private`:** Off by default and for local testing only. It
  unlocks private and loopback addresses, but link-local addresses such as
  `169.254.169.254` stay blocked always.
- **Alternatives considered:** Allowing IPs on a per-request basis. Rejected
  because a single flag is easier to audit.
- **Known gap:** net-guard returns the validated IPs, but later modules must
  connect to those IPs and not look the name up again. This prevents DNS
  rebinding and is enforced in Phase 3 (HTTP).

  ## HTTP module (Phase 3)

- **Decision:** The HTTP module connects only to an IP that net-guard has
  already validated. A custom `lookup` on the request always returns that IP,
  so the hostname is never resolved a second time.
- **Why:** Resolving twice allows DNS rebinding. A hostname could resolve to a
  public IP during validation and to an internal IP when connecting.
- **Redirects:** Followed manually, up to 5 hops. net-guard runs on every hop,
  so a redirect to an internal address (for example `169.254.169.254`) is
  blocked. Only `http:` and `https:` are followed.
- **Body size:** The response body is never downloaded. The connection is
  closed as soon as the status and headers arrive, which also caps memory use.
- **Timeout:** A hard timeout covers the whole request (10 seconds by default).
- **Cookies:** Only the name and the Secure, HttpOnly, and SameSite flags are
  recorded. Cookie values are never stored, because they may be session
  secrets.
- **TLS errors:** Certificate errors are reported as `TLS_ERROR` and are never
  bypassed by the HTTP client. Reading certificate details from invalid
  certificates is the TLS module's job (Phase 5).
- **Alternatives considered:** Following redirects automatically with the HTTP
  library. Rejected because it would skip the per-hop net-guard check.
- **Known gap:** Only the first resolved IP is used, with no fallback to the
  others. Acceptable for v1.

## TCP module (Phase 4)

- **Decision:** Port checks connect only to an IP that net-guard has already
  validated. The check connects, notes the result, and closes. No data is sent
  or read, so no banners or service details are collected.
- **Port allowlist:** Users can only request ports from a fixed allowlist
  (the 9 defaults plus a few common service ports). Anything else is rejected
  before any connection is made.
- **Why:** Without an allowlist, Sentinel would be a general-purpose port
  scanner that anyone could aim at arbitrary ports.
- **Limits:** At most 5 connections run at once, with a 3 second timeout per
  port. This keeps scans gentle on the target.
- **States:** `open`, `closed` (connection refused), `timeout` (no answer,
  often a firewall), and `error` (anything else).
- **Open ports are informational:** An open port is not a vulnerability. The
  finding engine (Phase 6) will report open ports as informational only, and
  only raise severity when there is supporting context.
- **Alternatives considered:** Allowing any port from 1 to 65535. Rejected
  because it turns the tool into an unrestricted scanner, which is out of
  scope for v1.
- **Known gap:** Only the first resolved IP is checked, as in the HTTP module.

## TLS module (Phase 5)

- **Decision:** The TLS module connects with `rejectUnauthorized: false`. This
  is the only place in Sentinel where certificate verification is turned off,
  and it is for observation only.
- **Why:** With verification on, an expired, self-signed, or mismatched
  certificate makes the handshake fail, so there is nothing left to read or
  report. Those are exactly the cases the scanner exists to find.
- **What keeps this safe:**
  - No data is sent after the handshake. The connection is closed as soon as
    the certificate has been read, so nothing sensitive can be sent to an
    unverified server.
  - Validity is computed separately (expiry, self-signed, hostname match) and
    reported in an `analysis` block. A failed check becomes a finding in
    Phase 6, never a silent pass.
  - The connection goes only to the IP net-guard already validated, so a
    hostname is never resolved a second time.
- **The HTTP module is different:** It does not bypass certificate checks.
  A bad certificate there is reported as `TLS_ERROR`. Only this module is
  allowed to observe invalid certificates.
- **Self-signed detection:** A certificate is treated as self-signed when its
  subject and issuer are identical. This does not verify the signature, so it
  is a heuristic.
- **Hostname matching:** Uses Node's `checkServerIdentity`, which handles
  wildcards and IP addresses correctly. Not hand-written.
- **Expiry thresholds:** This module only reports `daysUntilExpiry`. The 30,
  14, and 7 day thresholds and their severities are applied by the finding
  engine in Phase 6.
- **Alternatives considered:** Connecting with verification on and parsing the
  error code. Rejected because the certificate details would be unavailable
  exactly when they matter most.
- **Known gaps:** Only the leaf certificate is analyzed, not the full chain.
  Only port 443 is checked by default, and only the first resolved IP is used.

## Finding engine (Phase 6)

- **Decision:** Findings are produced by pure functions. A rule takes a scan
  result and returns a list of findings, with no network access and no side
  effects. The same scan always gives the same findings in the same order.
- **Why:** Pure rules are easy to test, easy to audit, and cannot be abused to
  make extra connections.
- **Evidence-based wording:** Findings say "observed" or "not observed", never
  "vulnerable". The scanner sees configuration, not exploitability, so a
  finding describes what was seen and why it may matter.
- **Every finding has evidence and remediation.** The tests enforce this.
- **No guessing on failures:** When a check failed (timeout, DNS error,
  blocked target), the matching rules produce nothing. A failed lookup is not
  treated as proof that a record or header is missing.
- **Open ports are informational only.** An open port alone is not a
  weakness, so it is never rated above informational.
- **Severity:** Expired certificate and 7 days or less to expiry are high.
  14 days or less is medium and 30 days or less is low. Missing headers and
  cookie flags are low. Self-signed and hostname mismatch are medium.
- **Untrusted data:** Header values and certificate fields come from the
  target and may contain hostile text. Stored evidence is length-capped, and
  values are kept as plain data. The dashboard must render evidence as text,
  never as HTML (Phase 12).
- **Stable IDs:** Rule IDs live in one registry and are never reused or
  renumbered. A test checks for duplicates.
- **CLI exit code:** `1` when any finding is low or higher, `0` otherwise.
  Informational findings do not change the exit code.
- **Alternatives considered:** A scoring system that rolls findings into one
  grade. Rejected for v1 because a single number hides the evidence.
- **Known gaps:** Header checks are presence checks, not quality checks. For
  example, a weak CSP counts as present. The finding engine is also not yet
  covered by tests against real-world responses.
