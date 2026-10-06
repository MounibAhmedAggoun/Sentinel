import { RULE_IDS } from '../ids.js';
import type { CookieInfo } from '../../http/types.js';
import type { Finding, Rule } from '../types.js';

interface SeenCookie extends CookieInfo {
  /** True when the cookie was set on an HTTPS response. */
  overHttps: boolean;
}

/** Collects cookies from every hop, keeping the first one seen for each name. */
function collectCookies(hops: { url: string; cookies: CookieInfo[] }[]): SeenCookie[] {
  const seen = new Map<string, SeenCookie>();
  for (const hop of hops) {
    for (const cookie of hop.cookies) {
      if (!seen.has(cookie.name)) {
        seen.set(cookie.name, { ...cookie, overHttps: hop.url.startsWith('https:') });
      }
    }
  }
  return [...seen.values()];
}

function cookieFinding(
  ruleId: string,
  flag: string,
  names: string[],
  why: string,
  remediation: string,
): Finding {
  return {
    ruleId,
    title: `Cookie flag not observed: ${flag}`,
    severity: 'low',
    description: `${names.length} cookie(s) were set without the ${flag} flag. ${why}`,
    evidence: { flag, cookies: names },
    remediation,
  };
}

export const cookieRules: Rule = (scan) => {
  if (scan.http.error !== null) return [];

  const cookies = collectCookies(scan.http.hops);
  const findings: Finding[] = [];

  // Secure only matters for cookies set over HTTPS.
  const noSecure = cookies.filter((c) => c.overHttps && !c.secure).map((c) => c.name);
  if (noSecure.length > 0) {
    findings.push(
      cookieFinding(
        RULE_IDS.COOKIE_SECURE_MISSING,
        'Secure',
        noSecure,
        'Without it, a browser may send the cookie over unencrypted HTTP connections.',
        'Consider adding the Secure flag to cookies that are set over HTTPS.',
      ),
    );
  }

  const noHttpOnly = cookies.filter((c) => !c.httpOnly).map((c) => c.name);
  if (noHttpOnly.length > 0) {
    findings.push(
      cookieFinding(
        RULE_IDS.COOKIE_HTTPONLY_MISSING,
        'HttpOnly',
        noHttpOnly,
        'Without it, scripts running in the page can read the cookie. Some cookies are meant to be read by scripts, so this may be intentional.',
        'Review whether each cookie needs to be readable by scripts, and add HttpOnly if it does not.',
      ),
    );
  }

  const noSameSite = cookies.filter((c) => c.sameSite === null).map((c) => c.name);
  if (noSameSite.length > 0) {
    findings.push(
      cookieFinding(
        RULE_IDS.COOKIE_SAMESITE_MISSING,
        'SameSite',
        noSameSite,
        'Without it, the browser applies its own default for when the cookie is sent with cross-site requests.',
        'Consider setting SameSite=Lax or SameSite=Strict, unless the cookie must be sent cross-site.',
      ),
    );
  }

  return findings;
};
