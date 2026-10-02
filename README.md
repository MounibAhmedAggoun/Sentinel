# Sentinel

Web security reconnaissance and monitoring platform.

> **Authorized use only.** Scan only systems you own or have explicit
> written permission to test.

## Features

_Coming soon._

## Architecture

```
core      shared types and finding rules
scanner   DNS, TCP, HTTP, TLS modules
cli       command-line interface
api       REST API and authentication
frontend  React dashboard
docs      threat model and security decisions
```

## Tech Stack

Node.js, TypeScript, Express, PostgreSQL, React, Zod, Vitest, Docker Compose.

## Installation

```bash
git clone https://github.com/MounibAhmedAggoun/Sentinel.git
cd Sentinel
npm install
```

## Development

```bash
npm run check   # lint + format check + typecheck + tests
```

## Usage

_Coming in Phase 1._

## Example Report

_Coming in Phase 7._

## Security Model

See `docs/threat-model.md` (in progress).

## Authorized Use

Sentinel performs controlled, defensive reconnaissance. Do not use it against
systems you do not own or lack permission to test.

## Testing

`npm test` runs the Vitest suite.

## Limitations

_To be documented as the project grows._

## Roadmap

_Coming soon._

## License

MIT
