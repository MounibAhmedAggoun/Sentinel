# Sentinel

Web security reconnaissance and monitoring platform.

> **Authorized use only.** Scan only systems you own or have explicit
> written permission to test.

## Features

- DNS lookups (A, AAAA, MX, NS, TXT, CAA) with SPF and DMARC parsing
- HTTP/HTTPS checks with manual redirect handling, status, headers, and cookie flags
- TCP checks on an allowlist of ports, with a 3 second timeout and concurrency of 5
- TLS certificate analysis: expiry, self-signed, and hostname mismatch
- Evidence-based findings with remediation guidance, never "vulnerable" claims
- Versioned JSON reports, validated with zod and published as JSON Schema
- Built-in SSRF protection: private, loopback, link-local, and reserved addresses are blocked

## Architecture

```
core      shared types and net-guard (SSRF protection)
scanner   DNS, TCP, HTTP, TLS modules, finding engine, reports
cli       command-line interface
api       REST API and authentication (planned)
frontend  React dashboard (planned)
docs      threat model, security decisions, report schema, sample report
```

The CLI and API call the same scanner engine. Scanner logic stays independent of
Express and React.

## Tech Stack

Node.js, TypeScript, Zod, Vitest. Planned: Express, PostgreSQL, React, Docker Compose.

## Installation

```bash
git clone https://github.com/MounibAhmedAggoun/Sentinel.git
cd Sentinel
npm install
```

Requires Node.js 20 or newer.

## Usage

```bash
# Scan a target you are authorized to test
npx tsx cli/src/index.ts scan example.com

# Check specific ports (must be on the allowlist)
npx tsx cli/src/index.ts scan example.com --ports 80,443

# Also write the full report to a JSON file
npx tsx cli/src/index.ts scan example.com --json reports/example.json

# Check that a file is a valid Sentinel report
npx tsx cli/src/index.ts validate reports/example.json
```

Exit codes: `0` clean, `1` findings of low severity or higher, `2` usage error,
`3` scan error.

`--allow-private` permits private and loopback addresses for local testing only.
Link-local addresses such as `169.254.169.254` are always blocked.

## Example Report

- [`docs/example-report.json`](docs/example-report.json): a real scan of `example.com`
- [`docs/report.schema.json`](docs/report.schema.json): the report format as JSON Schema

## Security Model

Every target passes a shape check and then net-guard, which resolves the name and
rejects private, loopback, link-local, and reserved addresses. Connections go only
to the IP that was validated, and redirects are re-checked on every hop. See
[`docs/security-decisions.md`](docs/security-decisions.md) and
[`docs/threat-model.md`](docs/threat-model.md) (in progress).

## Authorized Use

Sentinel performs controlled, defensive reconnaissance. Do not use it against
systems you do not own or lack permission to test.

## Development

```bash
npm run check   # lint, format check, type check, tests
npm test        # tests only
npm run export-schema   # regenerate docs/report.schema.json
```

## Limitations

- Only the first resolved IP of a target is scanned.
- Header checks test presence, not quality (a weak CSP still counts as present).
- Only the leaf TLS certificate is analyzed, not the full chain.
- Self-signed detection compares subject and issuer, and does not verify signatures.
- No scheduling, diffing, or dashboard yet.

## Roadmap

- v0.2: REST API, PostgreSQL, authentication, and domain verification
- v0.3: React dashboard and Docker Compose
- v1.0: hardening, full threat model, and release
- Later: scheduled rescans and "new since last scan" diffing

## License

MIT
