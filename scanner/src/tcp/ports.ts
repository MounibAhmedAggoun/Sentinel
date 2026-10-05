export const DEFAULT_PORTS = [21, 22, 25, 80, 443, 3306, 5432, 8080, 8443] as const;

/** Only these ports can be requested. Keeps Sentinel from becoming a general port scanner. */
export const ALLOWED_PORTS: ReadonlySet<number> = new Set([
  ...DEFAULT_PORTS,
  23,
  53,
  110,
  143,
  465,
  587,
  993,
  995,
  3389,
  6379,
  8000,
  27017,
]);

export type ParsePortsResult = { ok: true; ports: number[] } | { ok: false; error: string };

/** Parses a list like "80,443,8080". Rejects anything that is not on the allowlist. */
export function parsePorts(input: string): ParsePortsResult {
  const parts = input.split(',').map((part) => part.trim());
  const ports: number[] = [];

  for (const part of parts) {
    if (!/^\d{1,5}$/.test(part)) {
      return { ok: false, error: `invalid port: ${JSON.stringify(part)}` };
    }
    const port = Number(part);
    if (!ALLOWED_PORTS.has(port)) {
      return { ok: false, error: `port ${port} is not on the allowed list` };
    }
    if (!ports.includes(port)) ports.push(port);
  }

  return { ok: true, ports };
}
