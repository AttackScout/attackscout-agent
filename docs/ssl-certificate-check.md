# Check certificate expiry and weak keys on the server (PEM files)

`attackscout-agent scan` reads PEM certificate files and reports expiry and weak cryptography. Use it to catch a certificate that is about to expire before visitors see a browser warning.

```sh
attackscout-agent scan --cert /etc/ssl/site.pem
```

Certificates named by `ssl_certificate` (nginx) or `SSLCertificateFile` (Apache) in the configuration are added automatically. If none is found, the check is `not_checked`.

## What is reported

| ID | Severity | Meaning |
|---|---|---|
| `cert-expired` | critical | The first certificate of the file has expired |
| `cert-chain-expired` | high | A later certificate of the chain has expired |
| `cert-expiring` | high | The first certificate expires in less than 30 days |
| `cert-weak-key` | high | RSA under 2048 bits, ECDSA under 256 bits, or DSA |
| `cert-weak-signature` | medium | MD5 or SHA-1 signature |
| `cert-valid` | info | Valid certificate, with its end date and days left |
| `cert-unreadable` | low | File not readable by this user, or no PEM certificate in it |

Private keys found in the same file are skipped and never printed.

## Files, not connections

The tool reads files on disk. It does not connect to your site, so it does not test the TLS versions or cipher suites offered, and it cannot tell which certificate the Internet actually receives (a CDN or load balancer may serve another one). To check what is served, test from the outside.

## Fix

Renew the certificate and reload the web server. For a weak key or signature, reissue the certificate with an RSA key of at least 2048 bits (or ECDSA P-256) and a SHA-256 signature.

---

## Check your site from the outside too

attackscout-agent sees the inside of your server. To see what the Internet sees of your domain, run the free external audit at [attackscout.com/en](https://attackscout.com/en?utm_source=attackscout-agent&utm_medium=docs&utm_campaign=docs).

[Documentation index](index.md) | [Headers](web-server-security-headers.md) | [Exposed files](exposed-files-web-root.md) | [Command line](command-line-reference.md)
