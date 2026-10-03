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
