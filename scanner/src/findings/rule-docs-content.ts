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
  'HTTP-006': {
    why: 'The Server header sometimes names the web server software together with its version. Knowing the exact version lets someone look up issues that were published for it, so removing the version detail gives away less. Keeping the software up to date matters more than hiding the version.',
    falsePositives:
      'The rule matches version-like text such as 2.4 or 1.18, not a confirmed software version, so a value that merely looks like a version can match. The header may come from a proxy or CDN in front of the server rather than from the origin server. Hiding the version does not change which version is running.',
    fixes: [
      {
        server: 'nginx',
        snippet: `# In the http block.
server_tokens off;`,
      },
      {
        server: 'Apache',
        snippet: `# In the main server configuration, not in .htaccess.
ServerTokens Prod
ServerSignature Off`,
      },
      {
        server: 'Caddy',
        snippet: `# Inside the site block.
header -Server`,
      },
    ],
    references: [
      {
        title: 'nginx: server_tokens',
        url: 'https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens',
      },
      {
        title: 'Apache: ServerTokens',
        url: 'https://httpd.apache.org/docs/current/mod/core.html#servertokens',
      },
    ],
  },

  'HTTP-007': {
    why: 'The X-Powered-By header is often added by an application framework and names it, sometimes with a version. It tells an outside observer which technology is in use and can help them look up issues for that exact version. Keeping the software up to date matters more than hiding the header.',
    falsePositives:
      'The rule matches version-like text, so a value that only looks like a version can match. The header may be added by a layer in front of the application. Removing the header does not change what software is running.',
    fixes: [
      {
        server: 'nginx',
        snippet: `# Hides the header when it comes from a proxied application.
proxy_hide_header X-Powered-By;
# For FastCGI backends such as PHP-FPM:
# fastcgi_hide_header X-Powered-By;`,
      },
      {
        server: 'Apache',
        snippet: `# Needs mod_headers.
Header always unset X-Powered-By`,
      },
      {
        server: 'Caddy',
        snippet: `header -X-Powered-By`,
      },
      {
        server: 'Express',
        snippet: `app.disable('x-powered-by');`,
      },
    ],
    references: [
      {
        title: 'Express: Production best practices (security)',
        url: 'https://expressjs.com/en/advanced/best-practice-security.html',
      },
    ],
  },

  'HTTP-008': {
    why: 'A visitor who types a plain http:// address, or follows an old http:// link, reaches the site over an unencrypted connection first. If the server answers there without redirecting to HTTPS, the visitor can stay on plain HTTP. A redirect moves them to HTTPS, and an HSTS header then keeps later visits on HTTPS.',
    falsePositives:
      'Sentinel makes a separate request to the http:// address and follows redirects. The rule applies only when that request got a response and the last response was still plain HTTP. A host that does not answer on port 80 is skipped rather than judged. A service that is meant to be plain HTTP only, such as an internal tool, can match without being a problem.',
    fixes: [
      {
        server: 'nginx',
        snippet: `server {
    listen 80;
    server_name example.com www.example.com;
    return 301 https://$host$request_uri;
}`,
      },
      {
        server: 'Apache',
        snippet: `<VirtualHost *:80>
    ServerName example.com
    ServerAlias www.example.com
    Redirect permanent / https://example.com/
</VirtualHost>`,
      },
      {
        server: 'Caddy',
        snippet: `# Caddy redirects HTTP to HTTPS by default for a site with a hostname.
# This makes it explicit:
http://example.com {
    redir https://example.com{uri} permanent
}`,
      },
      {
        server: 'Express',
        snippet: `// Needs app.set('trust proxy', 1) when behind a proxy, so req.secure is correct.
app.use((req, res, next) => {
  if (req.secure) return next();
  res.redirect(301, 'https://example.com' + req.originalUrl);
});`,
      },
    ],
    references: [
      {
        title: 'MDN: Redirections in HTTP',
        url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections',
      },
    ],
  },

  'HTTP-009': {
    why: 'Strict-Transport-Security tells a browser to use HTTPS only for the length of its max-age. A short max-age means the browser forgets the instruction sooner, and a header with no max-age value may be ignored by browsers. A longer value keeps visitors on HTTPS for longer between visits.',
    falsePositives:
      'A max-age of 0 is sometimes set on purpose, to make browsers forget an earlier HSTS setting while a site is being moved back to HTTP. A short value is also a reasonable choice while HSTS is being rolled out. Sentinel flags values below 180 days and reads one response only.',
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
        url: 'https://datatracker.ietf.org/doc/html/rfc6797',
      },
    ],
  },

  'HTTP-010': {
    why: 'A Content-Security-Policy limits where scripts may come from. Sources such as unsafe-inline, unsafe-eval or a bare * widen what the policy allows, so a script injected into a page may still be permitted to run. The policy is then present, but it gives less protection against cross-site scripting.',
    falsePositives:
      'Sentinel reads script-src, or default-src when script-src is absent. It ignores unsafe-inline when a nonce, a hash or strict-dynamic is also present, because browsers ignore it then. A policy set through a meta tag, or one sent only on some responses, is not seen. A site may accept these sources for a time while it moves to nonces or hashes.',
    fixes: [
      {
        server: 'nginx',
        snippet: `# Static hash of an inline script. Replace the placeholder with the real hash.
# A per-request nonce needs the application to generate it.
add_header Content-Security-Policy "script-src 'self' 'sha256-REPLACE_WITH_HASH'" always;`,
      },
      {
        server: 'Apache',
        snippet: `# Needs mod_headers.
Header always set Content-Security-Policy "script-src 'self' 'sha256-REPLACE_WITH_HASH'"`,
      },
      {
        server: 'Caddy',
        snippet: `header Content-Security-Policy "script-src 'self' 'sha256-REPLACE_WITH_HASH'"`,
      },
      {
        server: 'Express',
        snippet: `import crypto from 'node:crypto';

app.use((req, res, next) => {
  const nonce = crypto.randomBytes(16).toString('base64');
  res.locals.nonce = nonce;
  res.setHeader('Content-Security-Policy', "script-src 'self' 'nonce-" + nonce + "'");
  next();
});
// In a template: <script nonce="...the value of res.locals.nonce...">`,
      },
    ],
    references: [
      {
        title: 'MDN: Content-Security-Policy',
        url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy',
      },
      {
        title: 'MDN: script-src',
        url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src',
      },
      {
        title: 'CSP Evaluator',
        url: 'https://csp-evaluator.withgoogle.com/',
      },
    ],
  },
  'COOKIE-001': {
    why: 'The Secure flag tells a browser to send a cookie only over HTTPS. A cookie set over HTTPS without it may also be sent over an unencrypted http:// connection, where someone on the network path could read it. This matters most for session cookies.',
    falsePositives:
      'Sentinel makes anonymous requests, so it only sees cookies the site sets before any login. It checks cookies set on HTTPS responses and keeps the first one seen for each name. A cookie that carries no sensitive value, such as a language preference, can match without being a problem.',
    fixes: [
      {
        server: 'nginx',
        snippet: `# For proxied applications. Needs nginx 1.19.3 or newer.
proxy_cookie_flags ~ secure;`,
      },
      {
        server: 'Apache',
        snippet: `# Needs mod_headers. Appends the flag to every cookie, so it can
# duplicate a flag the application already sets.
Header always edit Set-Cookie ^(.*)$ $1;Secure`,
      },
      {
        server: 'Express',
        snippet: `res.cookie('sid', value, { secure: true });
// Behind a proxy, also set app.set('trust proxy', 1).`,
      },
    ],
    references: [
      {
        title: 'MDN: Set-Cookie',
        url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie',
      },
      {
        title: 'OWASP: Session Management Cheat Sheet',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html',
      },
    ],
  },

  'COOKIE-002': {
    why: 'The HttpOnly flag keeps a cookie out of reach of scripts running in the page. Without it, a script that gets injected into the page, for example through cross-site scripting, can read the cookie. This matters most for session cookies.',
    falsePositives:
      'Some cookies are meant to be read by page scripts, such as a token that a script copies into a request header. For those, the missing flag is intentional. Sentinel cannot tell which cookies are session cookies, and it only sees cookies set on anonymous requests.',
    fixes: [
      {
        server: 'nginx',
        snippet: `# For proxied applications. Needs nginx 1.19.3 or newer.
proxy_cookie_flags ~ httponly;`,
      },
      {
        server: 'Apache',
        snippet: `# Needs mod_headers. Appends the flag to every cookie, so it can
# duplicate a flag the application already sets.
Header always edit Set-Cookie ^(.*)$ $1;HttpOnly`,
      },
      {
        server: 'Express',
        snippet: `res.cookie('sid', value, { httpOnly: true });`,
      },
    ],
    references: [
      {
        title: 'MDN: Set-Cookie',
        url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie',
      },
      {
        title: 'OWASP: Session Management Cheat Sheet',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html',
      },
    ],
  },

  'COOKIE-003': {
    why: 'The SameSite attribute tells a browser whether to send a cookie with requests that start on other sites. Setting it to Lax or Strict limits that, which reduces some cross-site request forgery risks. Without the attribute, the browser applies its own default.',
    falsePositives:
      'Current browsers treat a cookie without SameSite as Lax, so the real difference is smaller than it once was. Older browsers may behave differently. Setting the attribute mostly makes the behaviour explicit. A cookie that must be sent cross-site, such as one used in an embedded widget, needs SameSite=None with Secure.',
    fixes: [
      {
        server: 'nginx',
        snippet: `# For proxied applications. Needs nginx 1.19.3 or newer.
proxy_cookie_flags ~ samesite=lax;`,
      },
      {
        server: 'Apache',
        snippet: `# Needs mod_headers. Appends the attribute to every cookie, so it can
# duplicate one the application already sets.
Header always edit Set-Cookie ^(.*)$ $1;SameSite=Lax`,
      },
      {
        server: 'Express',
        snippet: `res.cookie('sid', value, { sameSite: 'lax' });`,
      },
    ],
    references: [
      {
        title: 'MDN: Set-Cookie (SameSite)',
        url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#samesitesamesite-value',
      },
      {
        title: 'OWASP: SameSite cookie attribute',
        url: 'https://owasp.org/www-community/SameSite',
      },
    ],
  },

  'COOKIE-004': {
    why: 'A cookie with SameSite=None is sent with cross-site requests, and browsers that enforce the current rules only accept such a cookie when it also has the Secure flag. Without Secure, the browser may reject the cookie, so the feature that depends on it may silently not work.',
    falsePositives:
      'Browsers differ in how strictly they enforce this, and older ones may still store the cookie. Sentinel only sees cookies set on anonymous requests and keeps the first one seen for each name. If the cookie never needs to be sent cross-site, the fix is to change SameSite rather than add Secure.',
    fixes: [
      {
        server: 'nginx',
        snippet: `# For proxied applications. Needs nginx 1.19.3 or newer.
proxy_cookie_flags ~ secure;`,
      },
      {
        server: 'Apache',
        snippet: `# Needs mod_headers. Appends the flag to every cookie, so it can
# duplicate a flag the application already sets.
Header always edit Set-Cookie ^(.*)$ $1;Secure`,
      },
      {
        server: 'Express',
        snippet: `res.cookie('widget', value, { sameSite: 'none', secure: true });`,
      },
    ],
    references: [
      {
        title: 'MDN: Set-Cookie (SameSite)',
        url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#samesitesamesite-value',
      },
    ],
  },
};
