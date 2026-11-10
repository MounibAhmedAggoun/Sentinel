import { judgedChain } from '../helpers.js';
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
  const chain = judgedChain(scan);
  if (chain === null) return [];

  const cookies = collectCookies(chain.hops);
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

  // Browsers reject SameSite=None cookies that lack the Secure flag.
  const noneWithoutSecure = cookies
    .filter((c) => c.sameSite === 'none' && !c.secure)
    .map((c) => c.name);
  if (noneWithoutSecure.length > 0) {
    findings.push({
      ruleId: RULE_IDS.COOKIE_SAMESITE_NONE_WITHOUT_SECURE,
      title: 'Cookie observed with SameSite=None but without Secure',
      severity: 'low',
      description: `${noneWithoutSecure.length} cookie(s) were set with SameSite=None but without the Secure flag. Browsers that enforce this rule reject such cookies, so they may not be stored at all.`,
      evidence: { sameSite: 'none', secure: false, cookies: noneWithoutSecure },
      remediation:
        'Add the Secure flag to these cookies, or use SameSite=Lax or SameSite=Strict if they do not need to be sent cross-site.',
    });
  }

  return findings;
};
