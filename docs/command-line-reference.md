# attackscout-agent command line reference: flags, statuses and exit codes

## Commands

```text
attackscout-agent scan [flags]       scan the server
attackscout-agent db update [flags]  download the OSV databases (network)
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
| `--json` | JSON output |
| `--fail-on SEV` | Exit 1 when a finding is at least `info`, `low`, `medium`, `high` or `critical`. Default `none` |
| `--lang LANG` | `en` (default) or `fr` |
| `--online` | Query api.osv.dev (sends package names, versions and ecosystems only) |
| `--db DIR` | OSV database directory. Default: user cache directory + `attackscout-agent` |

## db update flags

| Flag | Meaning |
|---|---|
| `--db DIR` | OSV database directory |
| `--ecosystems LIST` | Comma-separated. Default `npm,Packagist,PyPI,NuGet,Go` |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | A finding reached `--fail-on`, or `db update` failed for an ecosystem |
| `2` | Usage error: no command, unknown command or flag, unknown severity or language |

## Statuses and severities

Check statuses: `pass`, `fail`, `not_applicable`, `not_checked`. A check is `fail` when it has at least one finding of severity `low` or above. Severities: `info`, `low`, `medium`, `high`, `critical`.

Check identifiers in the JSON report: `end-of-life`, `vulnerabilities`, `sensitive-files`, `permissions`, `wp-config`, `web-server`, `certificates`.

See the guides: [end of life](end-of-life-software.md), [CVE](known-vulnerabilities-cve.md), [exposed files](exposed-files-web-root.md), [permissions](file-permissions.md), [headers](web-server-security-headers.md), [wp-config.php](wordpress-wp-config-security.md), [certificates](ssl-certificate-check.md).

---

## Check your site from the outside too

attackscout-agent sees the inside of your server. To see what the Internet sees of your domain, run the external audit at [attackscout.com/en](https://attackscout.com/en?utm_source=cli&utm_medium=docs&utm_campaign=attackscout-agent).

[Documentation index](index.md) | [CI](ci-integration.md) | [Network](offline-and-network.md)
