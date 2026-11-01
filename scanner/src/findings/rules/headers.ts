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

  // HSTS observed but with a short, zero, or missing max-age (HTTPS responses only).
  const hsts = isHttps ? headerValue(hop, 'strict-transport-security') : null;
  if (hsts !== null) {
    const minMaxAgeSeconds = 180 * 24 * 60 * 60;
    const match = /(?:^|;)\s*max-age\s*=\s*"?(\d+)"?/i.exec(hsts);
    const maxAge = match?.[1] !== undefined ? Number(match[1]) : null;
    if (maxAge === null || maxAge < minMaxAgeSeconds) {
      findings.push({
        ruleId: RULE_IDS.HTTP_HSTS_WEAK,
        title: 'Strict-Transport-Security observed with a short or missing max-age',
        severity: 'low',
        description:
          maxAge === null
            ? `The Strict-Transport-Security header was observed at ${hop.url} but no max-age value was found, so browsers may ignore it.`
            : `The Strict-Transport-Security header was observed at ${hop.url} with a max-age of ${maxAge} seconds, which is below the 180 days (${minMaxAgeSeconds} seconds) commonly recommended.`,
        evidence: {
          header: 'Strict-Transport-Security',
          value: hsts,
          maxAgeSeconds: maxAge,
          minimumSeconds: minMaxAgeSeconds,
          url: hop.url,
        },
        remediation:
          'Consider a max-age of at least 15552000 (180 days), and a longer value once the whole site is confirmed to work over HTTPS.',
      });
    }
  }

  // CSP observed but allowing weak script sources. Uses script-src, or default-src as the fallback.
  const cspHeader = headerValue(hop, 'content-security-policy');
  if (cspHeader !== null) {
    const directives = new Map<string, string[]>();
    for (const part of cspHeader.split(';')) {
      const [name, ...tokens] = part.trim().split(/\s+/);
      const key = name?.toLowerCase() ?? '';
      // Per the CSP spec, the first occurrence of a duplicated directive wins.
      if (key !== '' && !directives.has(key)) {
        directives.set(key, tokens);
      }
    }

    const directiveName = directives.has('script-src') ? 'script-src' : 'default-src';
    const scriptSources = (directives.get(directiveName) ?? []).map((s) => s.toLowerCase());

    // Browsers ignore 'unsafe-inline' when a nonce, hash, or 'strict-dynamic' is present.
    const hasNonceOrHash = scriptSources.some(
      (s) =>
        s.startsWith("'nonce-") ||
        s.startsWith("'sha256-") ||
        s.startsWith("'sha384-") ||
        s.startsWith("'sha512-") ||
        s === "'strict-dynamic'",
    );

    const weak: string[] = [];
    if (scriptSources.includes("'unsafe-inline'") && !hasNonceOrHash) weak.push("'unsafe-inline'");
    if (scriptSources.includes("'unsafe-eval'")) weak.push("'unsafe-eval'");
    if (scriptSources.includes('*')) weak.push('*');

    if (weak.length > 0) {
      findings.push({
        ruleId: RULE_IDS.HTTP_CSP_WEAK,
        title: 'Content-Security-Policy observed with weak script sources',
        severity: 'low',
        description: `The Content-Security-Policy header observed at ${hop.url} allows ${weak.join(', ')} in ${directiveName}, which weakens its protection against cross-site scripting.`,
        evidence: {
          header: 'Content-Security-Policy',
          directive: directiveName,
          weakSources: weak,
          value: cspHeader,
          url: hop.url,
        },
        remediation:
          "Consider removing these sources from script-src, and using nonces or hashes instead of 'unsafe-inline'.",
      });
    }
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
