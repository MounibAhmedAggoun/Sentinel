import { z } from 'zod';

export const SCHEMA_VERSION = '1.0';

const severity = z.enum(['informational', 'low', 'medium', 'high']);

const dnsError = z.object({ code: z.string(), message: z.string() });

function dnsLookup<T extends z.ZodType>(record: T) {
  return z.union([
    z.object({ ok: z.literal(true), records: z.array(record) }),
    z.object({ ok: z.literal(false), error: dnsError }),
  ]);
}

const dns = z.object({
  hostname: z.string(),
  a: dnsLookup(z.string()),
  aaaa: dnsLookup(z.string()),
  mx: dnsLookup(z.object({ exchange: z.string(), priority: z.number() })),
  ns: dnsLookup(z.string()),
  txt: dnsLookup(z.string()),
  caa: dnsLookup(z.object({ critical: z.boolean(), tag: z.string(), value: z.string() })),
  dmarcTxt: dnsLookup(z.string()),
  spf: z
    .object({ raw: z.string(), all: z.enum(['-all', '~all', '?all', '+all']).nullable() })
    .nullable(),
  dmarc: z
    .object({ raw: z.string(), policy: z.enum(['none', 'quarantine', 'reject']).nullable() })
    .nullable(),
});

const httpHop = z.object({
  url: z.string(),
  status: z.number(),
  headers: z.record(z.string(), z.union([z.string(), z.array(z.string())])),
  cookies: z.array(
    z.object({
      name: z.string(),
      secure: z.boolean(),
      httpOnly: z.boolean(),
      sameSite: z.enum(['strict', 'lax', 'none']).nullable(),
    }),
  ),
  remoteIp: z.string(),
  timingMs: z.number(),
});

const httpResult = z.object({
  startUrl: z.string(),
  finalUrl: z.string().nullable(),
  hops: z.array(httpHop),
  error: z.object({ code: z.string(), message: z.string() }).nullable(),
});

const portResult = z.object({
  port: z.number(),
  state: z.enum(['open', 'closed', 'timeout', 'error']),
  timingMs: z.number(),
  error: z.string().optional(),
});

const tcp = z.union([
  z.object({
    ok: z.literal(true),
    result: z.object({ ip: z.string(), ports: z.array(portResult) }),
  }),
  z.object({ ok: z.literal(false), error: z.object({ code: z.string(), message: z.string() }) }),
]);

const certName = z.object({
  commonName: z.string().nullable(),
  organization: z.string().nullable(),
});

const tls = z.union([
  z.object({
    ok: z.literal(true),
    result: z.object({
      ip: z.string(),
      protocol: z.string().nullable(),
      cipher: z.string().nullable(),
      certificate: z.object({
        subject: certName,
        issuer: certName,
        san: z.array(z.string()),
        validFrom: z.string(),
        validTo: z.string(),
        serialNumber: z.string(),
        fingerprint256: z.string(),
      }),
      analysis: z.object({
        expired: z.boolean(),
        daysUntilExpiry: z.number(),
        selfSigned: z.boolean(),
        hostnameMatches: z.boolean(),
      }),
    }),
  }),
  z.object({ ok: z.literal(false), error: z.object({ code: z.string(), message: z.string() }) }),
]);

const finding = z.object({
  ruleId: z.string(),
  title: z.string(),
  severity,
  description: z.string(),
  evidence: z.record(z.string(), z.unknown()),
  remediation: z.string(),
});

export const reportSchema = z.object({
  schemaVersion: z.literal(SCHEMA_VERSION),
  tool: z.object({ name: z.literal('sentinel'), version: z.string() }),
  target: z.string(),
  startedAt: z.iso.datetime(),
  finishedAt: z.iso.datetime(),
  durationMs: z.number().int().nonnegative(),
  dns,
  http: httpResult,
  httpPlain: httpResult,
  tcp,
  tls,
  findings: z.array(finding),
  /** Problems with the scan itself (a check that failed), as opposed to findings about the target. */
  errors: z.array(z.object({ module: z.string(), code: z.string(), message: z.string() })),
});

export type Report = z.infer<typeof reportSchema>;
