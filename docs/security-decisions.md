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
