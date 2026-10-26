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

export interface TlsAnalysis {
  expired: boolean;
  /** Whole days until expiry. Negative when already expired. */
  daysUntilExpiry: number;
  selfSigned: boolean;
  hostnameMatches: boolean;
  /**
   * The verdict Node's own TLS stack reaches when it checks this certificate
   * against the system's trusted root store, independent of our own heuristics.
   */
  trust: {
    authorized: boolean;
    /** OpenSSL-style code (e.g. "CERT_HAS_EXPIRED", "DEPTH_ZERO_SELF_SIGNED_CERT"). Null when authorized. */
    error: string | null;
  };
}

export interface TlsResult {
  ip: string;
  /** e.g. "TLSv1.3". */
  protocol: string | null;
  /** e.g. "TLS_AES_256_GCM_SHA384". */
  cipher: string | null;
  certificate: CertificateInfo;
  analysis: TlsAnalysis;
  /** Null when the legacy-protocol probe was not run for this scan. */
  legacyProtocols: LegacyProtocolProbe | null;
}

export type TlsOutcome = { ok: true; result: TlsResult } | { ok: false; error: TlsError };

export interface LegacyProtocolProbe {
  /** Protocol versions this server accepted when asked for exactly that version. */
  acceptedLegacyVersions: ('TLSv1' | 'TLSv1.1')[];
  /** True if the server did NOT accept a TLSv1.3 handshake when asked for exactly that version. */
  missingTls13: boolean;
}
