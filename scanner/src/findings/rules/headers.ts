import { RULE_IDS } from '../ids.js';
import { finalHop, headerValue } from '../helpers.js';
import type { Finding, Rule } from '../types.js';

const HEADER_NOT_OBSERVED = 'Security header not observed';

function missingHeader(
  ruleId: string,
  header: string,
  finalUrl: string,
  why: string,
  remediation: string,
): Finding {
  return {
    ruleId,
    title: `${HEADER_NOT_OBSERVED}: ${header}`,
    severity: 'low',
    description: `The ${header} header was not observed in the response from ${finalUrl}. ${why}`,
    evidence: { header, present: false, url: finalUrl },
    remediation,
  };
}

export const headerRules: Rule = (scan) => {
  const hop = finalHop(scan);
  if (hop === null) return [];

  const findings: Finding[] = [];
  const has = (name: string): boolean => headerValue(hop, name) !== null;
  const isHttps = hop.url.startsWith('https:');

  if (!has('content-security-policy')) {
    findings.push(
      missingHeader(
        RULE_IDS.HTTP_CSP_MISSING,
        'Content-Security-Policy',
        hop.url,
        'A CSP can limit which sources a page may load scripts and other content from, which reduces the impact of cross-site scripting.',
        'Review whether a Content-Security-Policy suits this site, and consider starting in report-only mode.',
      ),
    );
  }

  // HSTS is only meaningful over HTTPS, so it is not judged on plain HTTP responses.
  if (isHttps && !has('strict-transport-security')) {
    findings.push(
      missingHeader(
        RULE_IDS.HTTP_HSTS_MISSING,
        'Strict-Transport-Security',
        hop.url,
        'HSTS tells browsers to use HTTPS only, which protects against downgrade attempts.',
        'Consider adding Strict-Transport-Security with a suitable max-age once the whole site works over HTTPS.',
      ),
    );
  }

  const contentTypeOptions = headerValue(hop, 'x-content-type-options');
  if (contentTypeOptions === null || contentTypeOptions.toLowerCase() !== 'nosniff') {
    findings.push({
      ...missingHeader(
        RULE_IDS.HTTP_CONTENT_TYPE_OPTIONS_MISSING,
        'X-Content-Type-Options',
        hop.url,
        'The nosniff value stops browsers from guessing content types, which can reduce some content-confusion issues.',
        'Consider adding X-Content-Type-Options: nosniff.',
      ),
      evidence: {
        header: 'X-Content-Type-Options',
        present: contentTypeOptions !== null,
        value: contentTypeOptions,
        url: hop.url,
      },
    });
  }

  // Either X-Frame-Options or CSP frame-ancestors gives clickjacking protection.
  const csp = headerValue(hop, 'content-security-policy') ?? '';
  const hasFrameAncestors = /(^|;)\s*frame-ancestors\b/i.test(csp);
  if (!has('x-frame-options') && !hasFrameAncestors) {
    findings.push({
      ...missingHeader(
        RULE_IDS.HTTP_FRAME_PROTECTION_MISSING,
        'X-Frame-Options or CSP frame-ancestors',
        hop.url,
        'Without either, other sites may be able to embed this page in a frame, which can enable clickjacking.',
        'Consider adding a CSP frame-ancestors directive (or X-Frame-Options) that limits who can frame the site.',
      ),
      evidence: {
        xFrameOptionsPresent: false,
        cspFrameAncestorsPresent: false,
        url: hop.url,
      },
    });
  }

  if (!has('referrer-policy')) {
    findings.push(
      missingHeader(
        RULE_IDS.HTTP_REFERRER_POLICY_MISSING,
        'Referrer-Policy',
        hop.url,
        'Without a policy, browsers decide how much of the page URL is sent to other sites.',
        'Consider adding a Referrer-Policy such as strict-origin-when-cross-origin.',
      ),
    );
  }

  return findings;
};
