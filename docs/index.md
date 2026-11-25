# attackscout-agent documentation: server-side website security checks

attackscout-agent is a free, open source, read-only command line tool that checks a website from inside its server. It sends nothing over the network unless you run `db update` or `scan --online`. Start with the [README](../README.md) for installation and a first scan, then read the page for the check you care about.

## Guides by check

| Page | Question it answers |
|---|---|
| [End-of-life software](end-of-life-software.md) | How do I check if PHP, Node.js, WordPress or .NET on my server is end of life? |
| [Known vulnerabilities (CVE)](known-vulnerabilities-cve.md) | How do I find known CVEs in npm, Composer, PyPI, NuGet and Go dependencies on my server? |
| [Exposed files in the web root](exposed-files-web-root.md) | How do I find exposed .env, .git, SQL dumps, backups and phpinfo files? |
| [File permissions](file-permissions.md) | How do I find world-writable files and chmod 777 directories on a Linux web server? |
| [Web server security headers](web-server-security-headers.md) | How do I check HSTS, CSP and other security headers in nginx, Apache and IIS configuration? |
| [wp-config.php security](wordpress-wp-config-security.md) | How do I audit wp-config.php salts, WP_DEBUG and file editing? |
| [Certificate check](ssl-certificate-check.md) | How do I check certificate expiry and weak keys on the server? |

## Guides by use

| Page | Question it answers |
|---|---|
| [Use in CI](ci-integration.md) | How do I fail a pipeline on high security findings? |
| [Network and offline use](offline-and-network.md) | What does the tool send, and how do I run it offline? |
| [Command line reference](command-line-reference.md) | Which flags, statuses, severities and exit codes exist? |

## How results are reported

Every finding has a stable identifier, a severity (`info`, `low`, `medium`, `high`, `critical`), a message and a fix. Every check has one status: `pass`, `fail`, `not_applicable` or `not_checked`. A check that could not run is never reported as `pass`.

---

## Check your site from the outside too

attackscout-agent sees the inside of your server. To see what the Internet sees of your domain, run the external audit at [attackscout.com/en](https://attackscout.com/en?utm_source=cli&utm_medium=docs&utm_campaign=attackscout-agent).
