import { RULE_IDS } from '../ids.js';
import type { Finding, Rule } from '../types.js';

/** Expiry thresholds in days, checked from most to least urgent. */
function expirySeverity(days: number): Finding['severity'] | null {
  if (days <= 7) return 'high';
  if (days <= 14) return 'medium';
  if (days <= 30) return 'low';
  return null;
}

const DAY_MS = 86_400_000;

/**
 * CA/Browser Forum maximum validity (days) for a publicly trusted certificate,
 * by issue date (Ballot SC-081v3). Null before 2026-03-15, when the limit was
 * 398 days and is not checked here.
 */
function maxValidityDays(issuedAt: number): number | null {
  if (issuedAt >= Date.UTC(2029, 2, 15)) return 47;
  if (issuedAt >= Date.UTC(2027, 2, 15)) return 100;
  if (issuedAt >= Date.UTC(2026, 2, 15)) return 200;
  return null;
}

export const tlsRules: Rule = (scan) => {
  if (!scan.tls.ok) return [];

  const { certificate, analysis } = scan.tls.result;
  const findings: Finding[] = [];

  if (analysis.expired) {
    findings.push({
      ruleId: RULE_IDS.TLS_CERT_EXPIRED,
      title: 'Certificate expiry date has passed',
      severity: 'high',
      description: `The certificate served by ${scan.target} had an expiry date of ${certificate.validTo}, which is in the past. Browsers show a warning for expired certificates.`,
      evidence: {
        validTo: certificate.validTo,
        daysUntilExpiry: analysis.daysUntilExpiry,
        subject: certificate.subject.commonName,
      },
      remediation:
        'Renew or replace the certificate, and consider automated renewal so it does not lapse again.',
    });
  } else {
    const severity = expirySeverity(analysis.daysUntilExpiry);
    if (severity !== null) {
      findings.push({
        ruleId: RULE_IDS.TLS_CERT_EXPIRING,
        title: 'Certificate is close to its expiry date',
        severity,
        description: `The certificate served by ${scan.target} expires in ${analysis.daysUntilExpiry} day(s), on ${certificate.validTo}.`,
        evidence: {
          validTo: certificate.validTo,
          daysUntilExpiry: analysis.daysUntilExpiry,
          subject: certificate.subject.commonName,
        },
        remediation: 'Renew the certificate before it expires, and consider automated renewal.',
      });
    }
  }

  if (analysis.selfSigned) {
    findings.push({
      ruleId: RULE_IDS.TLS_CERT_SELF_SIGNED,
      title: 'Self-signed certificate observed',
      severity: 'medium',
      description: `The certificate served by ${scan.target} appears to be self-signed, meaning its subject and issuer match. Browsers do not trust self-signed certificates by default. This is expected on some internal or test systems.`,
      evidence: {
        subject: certificate.subject.commonName,
        issuer: certificate.issuer.commonName,
      },
      remediation:
        'If this is a public site, consider a certificate from a trusted certificate authority.',
    });
  }

  if (!analysis.hostnameMatches) {
    findings.push({
      ruleId: RULE_IDS.TLS_CERT_HOSTNAME_MISMATCH,
      title: 'Certificate does not list the scanned hostname',
      severity: 'medium',
      description: `The certificate served by ${scan.target} does not list that name in its subject or alternative names. Browsers show a warning when the name does not match.`,
      evidence: {
        hostname: scan.target,
        san: certificate.san,
        commonName: certificate.subject.commonName,
      },
      remediation:
        'Check that the certificate covers this hostname, or that the name is served by the intended server.',
    });
  }

  // Only reported when the certificate isn't already flagged above for a more
  // specific reason (expired, self-signed, hostname mismatch), since the
  // system trust store would reject it for those same reasons too - this
  // avoids three findings that all restate one underlying problem.
  const alreadyExplained = analysis.expired || analysis.selfSigned || !analysis.hostnameMatches;
  if (!analysis.trust.authorized && !alreadyExplained) {
    findings.push({
      ruleId: RULE_IDS.TLS_CERT_NOT_TRUSTED,
      title: 'Certificate not trusted by the system certificate store',
      severity: 'medium',
      description: `The certificate served by ${scan.target} was not verified against this system's trusted root certificates. Reason reported by the TLS library: ${analysis.trust.error ?? 'unknown'}. This commonly means an incomplete certificate chain (a missing intermediate certificate), or an unrecognized certificate authority.`,
      evidence: {
        subject: certificate.subject.commonName,
        issuer: certificate.issuer.commonName,
        reason: analysis.trust.error,
      },
      remediation:
        'Check that the server sends its full certificate chain, including any intermediate certificates, not just the leaf certificate.',
    });
  }

  const legacy = scan.tls.result.legacyProtocols;
  if (legacy !== null) {
    if (legacy.acceptedLegacyVersions.length > 0) {
      findings.push({
        ruleId: RULE_IDS.TLS_LEGACY_PROTOCOL_ACCEPTED,
        title: 'Outdated TLS protocol version accepted',
        severity: 'medium',
        description: `${scan.target} accepted a handshake using ${legacy.acceptedLegacyVersions.join(' and ')}, which modern browsers and clients no longer support by default. These versions have known weaknesses.`,
        evidence: { acceptedVersions: legacy.acceptedLegacyVersions },
        remediation: 'Disable TLS 1.0 and TLS 1.1 on the server, keeping TLS 1.2 and TLS 1.3 only.',
      });
    }

    if (legacy.missingTls13) {
      findings.push({
        ruleId: RULE_IDS.TLS_1_3_NOT_SUPPORTED,
        title: 'TLS 1.3 not observed as supported',
        severity: 'informational',
        description: `${scan.target} did not accept a handshake pinned to TLS 1.3, the current version with the best security and performance properties. Many servers still run only TLS 1.2, which remains secure.`,
        evidence: { missingTls13: true },
        remediation: 'Consider enabling TLS 1.3 if the server software supports it.',
      });
    }
  }

  // Only for certificates a public CA would have issued: self-signed and untrusted
  // certificates are not bound by the CA/Browser Forum limit.
  const issuedAt = Date.parse(certificate.validFrom);
  const expiresAt = Date.parse(certificate.validTo);
  if (
    !Number.isNaN(issuedAt) &&
    !Number.isNaN(expiresAt) &&
    !analysis.selfSigned &&
    analysis.trust.authorized
  ) {
    const maxDays = maxValidityDays(issuedAt);
    if (maxDays !== null && expiresAt - issuedAt > maxDays * DAY_MS) {
      findings.push({
        ruleId: RULE_IDS.TLS_VALIDITY_TOO_LONG,
        title: 'Certificate validity period observed above the CA/Browser Forum maximum',
        severity: 'informational',
        description: `The certificate served by ${scan.target} was issued on ${certificate.validFrom} and is valid until ${certificate.validTo}, which is longer than the ${maxDays} days that publicly trusted certificates issued on that date may have. This is unusual for a certificate from a public CA.`,
        evidence: {
          validFrom: certificate.validFrom,
          validTo: certificate.validTo,
          validityDays: Math.round((expiresAt - issuedAt) / DAY_MS),
          maximumDays: maxDays,
        },
        remediation:
          'Check which certificate authority issued this certificate. If it is a private CA, this limit does not apply.',
      });
    }
  }

  // The key and the signature of the certificate the server presented (the leaf only).
  const { keyType, keyBits, signatureAlgorithm } = certificate;

  if (keyType === 'rsa' && keyBits !== null && keyBits < 2048) {
    findings.push({
      ruleId: RULE_IDS.TLS_WEAK_RSA_KEY,
      title: 'Certificate observed with a short RSA key',
      severity: 'medium',
      description: `The certificate served by ${scan.target} has an RSA key of ${keyBits} bits. Keys shorter than 2048 bits are no longer considered strong enough, and current browsers and certificate authorities expect at least 2048.`,
      evidence: { keyType, keyBits, minimumBits: 2048 },
      remediation:
        'Consider issuing a new certificate with an RSA key of at least 2048 bits, or with an ECDSA key.',
    });
  }

  if (signatureAlgorithm !== null && /(?<![a-z0-9])sha-?1(?![0-9])|md5/i.test(signatureAlgorithm)) {
    findings.push({
      ruleId: RULE_IDS.TLS_WEAK_SIGNATURE_ALGORITHM,
      title: 'Certificate observed with a weak signature algorithm',
      severity: 'medium',
      description: `The certificate served by ${scan.target} is signed with ${signatureAlgorithm}. SHA-1 and MD5 signatures are considered weak, and browsers no longer trust certificates signed with them.`,
      evidence: { signatureAlgorithm },
      remediation: 'Consider replacing the certificate with one signed with SHA-256 or stronger.',
    });
  }

  // The server's choice during the handshake. This says nothing about HTTP/3 or about
  // whether HTTP/1.1 is a problem for this site, so it stays informational.
  const alpn = scan.tls.result.alpnProtocol;
  if (alpn !== 'h2') {
    findings.push({
      ruleId: RULE_IDS.TLS_HTTP2_NOT_OFFERED,
      title: 'HTTP/2 not observed as offered',
      severity: 'informational',
      description: `${scan.target} did not choose HTTP/2 when it was offered during the TLS handshake${alpn === null ? ' (no application protocol was chosen)' : ` (it chose ${alpn})`}. HTTP/1.1 still works. HTTP/2 can load pages faster over one connection.`,
      evidence: { alpnProtocol: alpn },
      remediation: 'Consider enabling HTTP/2 if the web server or proxy supports it.',
    });
  }

  return findings;
};
