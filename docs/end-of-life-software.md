# Check end-of-life software on a server (PHP, Node.js, WordPress, .NET, nginx, Apache, IIS)

Running a version that no longer gets security fixes is one of the most common server weaknesses. `attackscout-agent scan` reads the versions installed on the server and compares them with an end-of-life table embedded in the binary. `attackscout-agent db update` refreshes that table from [endoflife.date](https://endoflife.date) into the local cache; the report shows the date of the data it used.

```sh
attackscout-agent scan --root /var/www/site
```

## What it detects

| Product | Where the version comes from |
|---|---|
| PHP | `php -v`, else configuration hints (`php8.1-fpm` sockets, `/etc/php/X.Y`) |
| Node.js | `node --version`, else `.nvmrc` / `.node-version` |
| .NET | `dotnet --list-runtimes`, else `<TargetFramework>` in `.csproj` files |
| WordPress | `wp-includes/version.php`, plugins (plugin headers), themes (`style.css`) |
| Drupal | `core/lib/Drupal.php` or `includes/bootstrap.inc`, contrib modules and themes (`*.info.yml`) |
| Joomla | `administrator/manifests/files/joomla.xml`, components, modules, plugins, templates |
| PrestaShop | `app/AppKernel.php` or `config/settings.inc.php` |
| nginx | `nginx -v` |
| Apache httpd | `apache2 -v` or `httpd -v` |
| IIS | registry key `HKLM\SOFTWARE\Microsoft\InetStp` (Windows) |
| React, Next.js | lockfiles, else `node_modules/react/package.json` and `node_modules/next/package.json` |

## Finding identifiers

| ID | Severity | Meaning |
|---|---|---|
| `<product>-eol` | high | The branch no longer receives fixes |
| `<product>-eol-soon` | medium | End of life in less than 90 days |
| `<product>-patch-behind` | low | A newer patch release of the same branch exists (only when the version was read exactly) |
| `<product>-version` | info | Supported version, or a version the table does not know |

Each finding carries a certainty: `high` when the exact version was read, `medium` when it was deduced from a hint.

## Where the dates come from

The table is embedded in the binary (`go:embed`) and carries its date, printed in every report. It is based on endoflife.date (MIT) and vendor pages; a vendor date wins when it is earlier. The scan never downloads anything; run `attackscout-agent db update` to fetch the current endoflife.date data into the cache (`--db`), which the following scans use instead of the embedded table.

## Fix

Upgrade to a supported branch; each finding links to the vendor's support policy. CVEs for these products are a separate check: see [known vulnerabilities](known-vulnerabilities-cve.md).

---

## Check your site from the outside too

attackscout-agent sees the inside of your server. To see what the Internet sees of your domain, run the free external audit at [attackscout.com/en](https://attackscout.com/en?utm_source=attackscout-agent&utm_medium=docs&utm_campaign=docs).

[Documentation index](index.md) | [Exposed files](exposed-files-web-root.md) | [Headers](web-server-security-headers.md) | [Certificates](ssl-certificate-check.md) | [CI](ci-integration.md)
