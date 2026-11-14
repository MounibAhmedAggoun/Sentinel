import type { RuleId } from './ids.js';
import type { RuleDocContent } from './rule-docs.js';

/**
 * The written documentation for each rule. A rule without an entry here has no
 * page yet. Wording stays observational: it says what was seen and why it can
 * matter, never that a site is vulnerable.
 */
export const RULE_DOC_CONTENT: Partial<Record<RuleId, RuleDocContent>> = {
  'HTTP-001': {
    why: 'A Content-Security-Policy limits where a page may load scripts and other content from. Without one, the browser applies no such limit, so a script that gets injected into a page runs without restriction. It is one layer of defence against cross-site scripting, not a replacement for fixing the injection itself.',
    falsePositives:
      'Not every site gains much from one. A static site with no user input and no third-party content has less to protect. The header may also be sent only on some responses, or added by a proxy in front of the server. Sentinel reads one response: the last one of the HTTPS request after redirects, or of the plain HTTP request when HTTPS is unreachable.',
    fixes: [
      {
        server: 'nginx',
        snippet: `# In the server block. Report-only mode logs what would be blocked
# without blocking anything, so start there.
add_header Content-Security-Policy-Report-Only "default-src 'self'" always;`,
      },
      {
        server: 'Apache',
        snippet: `# Needs mod_headers.
Header always set Content-Security-Policy-Report-Only "default-src 'self'"`,
      },
      {
        server: 'Caddy',
        snippet: `header Content-Security-Policy-Report-Only "default-src 'self'"`,
      },
      {
        server: 'Express',
        snippet: `app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy-Report-Only', "default-src 'self'");
  next();
});`,
      },
    ],
    references: [
      {
        title: 'MDN: Content-Security-Policy',
        url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy',
      },
    ],
  },

  'HTTP-002': {
    why: 'Strict-Transport-Security tells a browser to use HTTPS only for a site, for a set time. Without it, a request that starts as http:// goes over plain HTTP before any redirect, which leaves a window in which someone on the network path could interfere.',
    falsePositives:
      'The header only means something on HTTPS, so Sentinel does not judge plain HTTP responses. Browsers remember the header for the whole max-age, so it should be enabled only when every page works over HTTPS. Adding includeSubDomains extends that to all subdomains, and it should be added only when they all use HTTPS too.',
    fixes: [
      {
        server: 'nginx',
        snippet: `add_header Strict-Transport-Security "max-age=31536000" always;`,
      },
      {
        server: 'Apache',
        snippet: `# Needs mod_headers.
Header always set Strict-Transport-Security "max-age=31536000"`,
      },
      {
        server: 'Caddy',
        snippet: `header Strict-Transport-Security "max-age=31536000"`,
      },
      {
        server: 'Express',
        snippet: `app.use((req, res, next) => {
  res.setHeader('Strict-Transport-Security', 'max-age=31536000');
  next();
});`,
      },
    ],
    references: [
      {
        title: 'MDN: Strict-Transport-Security',
        url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security',
      },
      {
        title: 'RFC 6797: HTTP Strict Transport Security',
        url: 'https://www.rfc-editor.org/rfc/rfc6797',
      },
    ],
  },

  'HTTP-003': {
    why: 'The value nosniff tells a browser to trust the content type the server declares, and not to guess a different one from the content. Without it, some browsers may treat a file as another type, which can reduce the protection that a correct content type gives.',
    falsePositives:
      'The practical effect on current browsers is small. The rule also reports a header that is present with a value other than nosniff, because only that exact value has the effect.',
    fixes: [
      { server: 'nginx', snippet: `add_header X-Content-Type-Options "nosniff" always;` },
      {
        server: 'Apache',
        snippet: `# Needs mod_headers.
Header always set X-Content-Type-Options "nosniff"`,
      },
      { server: 'Caddy', snippet: `header X-Content-Type-Options nosniff` },
      {
        server: 'Express',
        snippet: `app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  next();
});`,
      },
    ],
    references: [
      {
        title: 'MDN: X-Content-Type-Options',
        url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options',
      },
    ],
  },

  'HTTP-004': {
    why: 'If other sites can put a page in a frame, a visitor can be tricked into clicking something the page shows underneath a hidden frame, which is called clickjacking. Either an X-Frame-Options header or a frame-ancestors directive in a Content-Security-Policy limits who may frame the page.',
    falsePositives:
      'Some pages are meant to be embedded, such as widgets or payment forms, and the fix for those is to list the specific sites that may frame them. Sentinel counts either header as protection, so a site with one of them does not get this finding.',
    fixes: [
      {
        server: 'nginx',
        snippet: `# Allow framing only by the same site.
add_header Content-Security-Policy "frame-ancestors 'self'" always;
# Older browsers read this header instead.
add_header X-Frame-Options "SAMEORIGIN" always;`,
      },
      {
        server: 'Apache',
        snippet: `# Needs mod_headers.
Header always set Content-Security-Policy "frame-ancestors 'self'"
Header always set X-Frame-Options "SAMEORIGIN"`,
      },
      {
        server: 'Caddy',
        snippet: `header Content-Security-Policy "frame-ancestors 'self'"
header X-Frame-Options SAMEORIGIN`,
      },
      {
        server: 'Express',
        snippet: `app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', "frame-ancestors 'self'");
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  next();
});`,
      },
    ],
    references: [
      {
        title: 'MDN: CSP frame-ancestors',
        url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors',
      },
      {
        title: 'MDN: X-Frame-Options',
        url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options',
      },
    ],
  },

  'HTTP-005': {
    why: 'When a visitor follows a link, the browser decides how much of the current page address to send to the next site. Addresses can contain identifiers or tokens, so a Referrer-Policy makes that choice explicit.',
    falsePositives:
      'Current browsers already default to a fairly strict policy, so the real risk is smaller than it once was. Setting the header mostly makes the behaviour explicit and consistent across browsers.',
    fixes: [
      {
        server: 'nginx',
        snippet: `add_header Referrer-Policy "strict-origin-when-cross-origin" always;`,
      },
      {
        server: 'Apache',
        snippet: `# Needs mod_headers.
Header always set Referrer-Policy "strict-origin-when-cross-origin"`,
      },
      { server: 'Caddy', snippet: `header Referrer-Policy strict-origin-when-cross-origin` },
      {
        server: 'Express',
        snippet: `app.use((req, res, next) => {
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});`,
      },
    ],
    references: [
      {
        title: 'MDN: Referrer-Policy',
        url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy',
      },
    ],
  },
};
