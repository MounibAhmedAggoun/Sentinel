# Sentinel rules

| Rule                        | Severity                   | Finding                                                                 |
| --------------------------- | -------------------------- | ----------------------------------------------------------------------- |
| [HTTP-001](HTTP-001.md)     | low                        | Security header not observed: Content-Security-Policy                   |
| [HTTP-002](HTTP-002.md)     | low                        | Security header not observed: Strict-Transport-Security                 |
| [HTTP-003](HTTP-003.md)     | low                        | Security header not observed: X-Content-Type-Options                    |
| [HTTP-004](HTTP-004.md)     | low                        | Security header not observed: X-Frame-Options or CSP frame-ancestors    |
| [HTTP-005](HTTP-005.md)     | low                        | Security header not observed: Referrer-Policy                           |
| [HTTP-006](HTTP-006.md)     | informational              | Version information observed in Server header                           |
| [HTTP-007](HTTP-007.md)     | informational              | Version information observed in X-Powered-By header                     |
| [HTTP-008](HTTP-008.md)     | low                        | Redirect from HTTP to HTTPS not observed                                |
| [HTTP-009](HTTP-009.md)     | low                        | Strict-Transport-Security observed with a short or missing max-age      |
| [HTTP-010](HTTP-010.md)     | low                        | Content-Security-Policy observed with weak script sources               |
| [HTTP-011](HTTP-011.md)     | informational              | Strict-Transport-Security observed without includeSubDomains            |
| [HTTP-012](HTTP-012.md)     | informational              | Strict-Transport-Security observed without preload                      |
| [HTTP-013](HTTP-013.md)     | informational              | Content-Security-Policy observed without an object-src restriction      |
| [HTTP-014](HTTP-014.md)     | informational              | Content-Security-Policy observed without a base-uri directive           |
| [COOKIE-001](COOKIE-001.md) | low                        | Cookie flag not observed: Secure                                        |
| [COOKIE-002](COOKIE-002.md) | low                        | Cookie flag not observed: HttpOnly                                      |
| [COOKIE-003](COOKIE-003.md) | low                        | Cookie flag not observed: SameSite                                      |
| [COOKIE-004](COOKIE-004.md) | low                        | Cookie observed with SameSite=None but without Secure                   |
| [COOKIE-005](COOKIE-005.md) | low                        | Cookie observed with a __Secure- prefix but without Secure              |
| [COOKIE-006](COOKIE-006.md) | low                        | Cookie observed with a __Host- prefix that breaks its rules             |
| [TLS-001](TLS-001.md)       | high                       | Certificate expiry date has passed                                      |
| [TLS-002](TLS-002.md)       | low, medium, high          | Certificate is close to its expiry date                                 |
| [TLS-003](TLS-003.md)       | medium                     | Self-signed certificate observed                                        |
| [TLS-004](TLS-004.md)       | medium                     | Certificate does not list the scanned hostname                          |
| [TLS-005](TLS-005.md)       | medium                     | Certificate not trusted by the system certificate store                 |
| [TLS-006](TLS-006.md)       | medium                     | Outdated TLS protocol version accepted                                  |
| [TLS-007](TLS-007.md)       | informational              | TLS 1.3 not observed as supported                                       |
| [TLS-008](TLS-008.md)       | medium                     | Certificate observed with a short RSA key                               |
| [TLS-009](TLS-009.md)       | medium                     | Certificate observed with a weak signature algorithm                    |
| [TLS-010](TLS-010.md)       | informational              | HTTP/2 not observed as offered                                          |
| [TLS-011](TLS-011.md)       | informational              | Certificate validity period observed above the CA/Browser Forum maximum |
| [DNS-001](DNS-001.md)       | low                        | SPF record not observed                                                 |
| [DNS-002](DNS-002.md)       | low                        | DMARC record not observed                                               |
| [DNS-003](DNS-003.md)       | informational              | CAA record not observed                                                 |
| [DNS-004](DNS-004.md)       | medium                     | SPF record observed that allows any sender                              |
| [DNS-005](DNS-005.md)       | informational              | DMARC record observed with a monitoring-only policy                     |
| [DNS-006](DNS-006.md)       | low                        | SPF record observed without an enforcing policy                         |
| [DNS-007](DNS-007.md)       | low                        | More than one SPF record observed                                       |
| [DNS-008](DNS-008.md)       | low                        | SPF record observed with more than 10 DNS lookups                       |
| [DNS-009](DNS-009.md)       | informational              | DMARC record observed without a reporting address                       |
| [DNS-010](DNS-010.md)       | low                        | DMARC record observed with a partial pct                                |
| [DNS-011](DNS-011.md)       | low                        | DMARC record observed with a weaker subdomain policy                    |
| [TCP-001](TCP-001.md)       | informational              | TCP port &lt;port&gt; observed open                                     |
| [TCP-002](TCP-002.md)       | informational, low, medium | &lt;service&gt; port &lt;port&gt; observed open                         |
