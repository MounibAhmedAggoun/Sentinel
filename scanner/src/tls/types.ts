export type TlsErrorCode =
  'BLOCKED_TARGET' | 'TIMEOUT' | 'CONNECTION_FAILED' | 'NO_CERTIFICATE' | 'UNKNOWN';

export interface TlsError {
  code: TlsErrorCode;
  message: string;
}

export interface CertName {
  commonName: string | null;
  organization: string | null;
}

export interface CertificateInfo {
  subject: CertName;
  issuer: CertName;
  /** Subject Alternative Names, e.g. "example.com" or "*.example.com". */
  san: string[];
  /** ISO 8601 timestamps. */
  validFrom: string;
  validTo: string;
  serialNumber: string;
  fingerprint256: string;
}

/** What we computed ourselves, because the connection does not verify certificates. */
export interface TlsAnalysis {
  expired: boolean;
  /** Whole days until expiry. Negative when already expired. */
  daysUntilExpiry: number;
  selfSigned: boolean;
  hostnameMatches: boolean;
}

export interface TlsResult {
  ip: string;
  /** e.g. "TLSv1.3". */
  protocol: string | null;
  /** e.g. "TLS_AES_256_GCM_SHA384". */
  cipher: string | null;
  certificate: CertificateInfo;
  analysis: TlsAnalysis;
}

export type TlsOutcome = { ok: true; result: TlsResult } | { ok: false; error: TlsError };
