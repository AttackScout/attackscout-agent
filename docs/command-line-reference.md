# attackscout-agent command line reference: flags, statuses and exit codes

## Commands

```text
attackscout-agent scan [flags]       scan the server
attackscout-agent db update [flags]  download the OSV, CISA KEV and endoflife.date data (network)
attackscout-agent version            print the version
attackscout-agent help               print the usage
```

## scan flags

| Flag | Meaning |
|---|---|
| `--root DIR` | Web root. Default: from the nginx / Apache configuration, then `/var/www/html`, `/srv/www`, `/usr/share/nginx/html`, `/var/www` (`C:\inetpub\wwwroot` on Windows), then the current directory if it contains `wp-config.php`, `index.php`, `index.html`, `web.config`, `composer.json`, `package.json` or `wp-includes` |
| `--project DIR` | Extra directory with lockfiles or Terraform files (repeatable) |
| `--nginx DIR` | nginx configuration directory. Default: `/etc/nginx`, `/usr/local/etc/nginx`, `/opt/homebrew/etc/nginx` (`C:\nginx\conf`) |
| `--apache DIR` | Apache configuration directory. Default: `/etc/apache2`, `/etc/httpd`, `/usr/local/etc/httpd`, `/opt/homebrew/etc/httpd` (`C:\Apache24\conf`) |
| `--cert FILE` | PEM certificate to check (repeatable) |
| `--format F` | `text` (default), `json` or `sarif` (SARIF 2.1.0, for GitHub code scanning, GitLab and Azure DevOps) |
| `--json` | Same as `--format json` |
| `--output FILE` | Write the report to a file instead of the standard output |
| `--fail-on SEV` | Exit 1 when a finding is at least `critical`, `high`, `medium`, `low` or `info`. Default `none` |
| `--no-audit-link` | Hide the closing link to the free external audit (text output only; JSON and SARIF never contain it) |
| `--sysroot DIR` | Where the dpkg, rpm and apk databases and `etc/os-release` are read. Default `/` (none on Windows) |
| `--lang LANG` | `en` (default) or `fr` |
| `--online` | Query api.osv.dev (sends package names, versions and ecosystems only) |
| `--db DIR` | Database directory (OSV archives, CISA KEV, endoflife.date). Default: user cache directory + `attackscout-agent` |

## db update flags

| Flag | Meaning |
|---|---|
| `--db DIR` | Database directory |
| `--ecosystems LIST` | Comma-separated OSV ecosystems. Default `npm,Packagist,PyPI,NuGet,Go,RubyGems,Maven` plus the ecosystem of the system read in `/etc/os-release` (Debian, Ubuntu, Alpine, Red Hat, Rocky Linux, AlmaLinux, SUSE) |

`db update` also downloads the CISA KEV list and the endoflife.date data of each product; each source is reported on its own line.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | A finding reached `--fail-on`, or `db update` failed for a source |
| `2` | Usage error: no command, unknown command or flag, unknown format, severity or language, output file not writable |

## Statuses and severities

Check statuses: `pass`, `fail`, `not_applicable`, `not_checked`. A check is `fail` when it has at least one finding of severity `low` or above. Severities: `info`, `low`, `medium`, `high`, `critical`.

Check identifiers in the JSON report: `end-of-life`, `vulnerabilities`, `sensitive-files`, `phpinfo`, `permissions`, `wp-config`, `web-server`, `certificates`.

In SARIF, findings of severity `info` are left out; `critical` and `high` are `error`, `medium` is `warning`, `low` is `note`, and each rule carries a `security-severity` (the CVSS score, or 9.5 / 8.0 / 5.5 / 3.0).

See the guides: [end of life](end-of-life-software.md), [CVE](known-vulnerabilities-cve.md), [exposed files](exposed-files-web-root.md), [permissions](file-permissions.md), [headers](web-server-security-headers.md), [wp-config.php](wordpress-wp-config-security.md), [certificates](ssl-certificate-check.md).

---

## Check your site from the outside too

attackscout-agent sees the inside of your server. To see what the Internet sees of your domain, run the free external audit at [attackscout.com/en](https://attackscout.com/en?utm_source=attackscout-agent&utm_medium=docs&utm_campaign=docs).

[Documentation index](index.md) | [CI](ci-integration.md) | [Network](offline-and-network.md)
