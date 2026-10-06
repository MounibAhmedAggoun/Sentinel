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

  return findings;
};
