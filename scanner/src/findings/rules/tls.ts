import { RULE_IDS } from '../ids.js';
import type { Finding, Rule } from '../types.js';

/** Expiry thresholds in days, checked from most to least urgent. */
function expirySeverity(days: number): Finding['severity'] | null {
  if (days <= 7) return 'high';
  if (days <= 14) return 'medium';
  if (days <= 30) return 'low';
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

  return findings;
};
