# Check security headers (HSTS, CSP) and version disclosure in nginx, Apache and IIS configuration

`attackscout-agent scan` reads your web server configuration files and reports security headers that are not set and settings that disclose information.

```sh
attackscout-agent scan --nginx /etc/nginx --apache /etc/apache2 --root /var/www/site
```

## Which files are read

- **nginx**: the enabled sites (a file in `sites-available` that is not enabled is ignored), plus `conf.d`.
- **Apache**: the configuration directory, plus the `.htaccess` of the web root.
- **IIS**: the `web.config` of the web root, parsed as XML. If it cannot be parsed, the IIS part is reported `not_checked`.

## What is reported

| ID | Severity | Meaning |
|---|---|---|
| `header-hsts-missing` | medium | No `Strict-Transport-Security` |
| `header-csp-missing` | low | No `Content-Security-Policy` |
| `header-xcto-missing` | low | No `X-Content-Type-Options` |
| `header-frame-missing` | low | Neither `X-Frame-Options` nor CSP `frame-ancestors` |
| `header-referrer-missing` | low | No `Referrer-Policy` |
| `server-tokens` | low | nginx `server_tokens` not off, Apache `ServerTokens` not `Prod`, IIS `removeServerHeader` not set |
| `server-signature` | low | Apache `ServerSignature` not `Off` |
| `x-powered-by` | low | IIS sends `X-Powered-By` |
| `directory-listing` | medium | `autoindex on`, `Options Indexes`, IIS `directoryBrowse` |

## Example fixes

nginx:

```nginx
server_tokens off;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

Apache:

```apache
ServerTokens Prod
ServerSignature Off
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always set X-Content-Type-Options "nosniff"
```

Start a Content-Security-Policy in report-only mode before enforcing it, so that you do not break your pages.

## Limit: configuration, not live responses

The tool reads files. It does not request your site. A header added by a reverse proxy, a CDN or the application itself is not seen, and a header set in a file the tool does not read is reported missing. To see the headers a visitor actually receives, check from the outside.

---

## Check your site from the outside too

attackscout-agent sees the inside of your server. To see what the Internet sees of your domain, run the free external audit at [attackscout.com/en](https://attackscout.com/en?utm_source=attackscout-agent&utm_medium=docs&utm_campaign=docs).

[Documentation index](index.md) | [Certificates](ssl-certificate-check.md) | [Exposed files](exposed-files-web-root.md) | [Command line](command-line-reference.md)
