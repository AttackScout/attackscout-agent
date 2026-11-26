# attackscout-agent: website security check from the server (self-hosted security audit CLI)

[Français](README.fr.md) | [Documentation](docs/index.md)

**attackscout-agent is a free, open source, self-hosted security audit CLI.** Run it on a Linux, macOS or Windows server, or in CI, to check a website from the inside: known CVEs in lockfiles and system packages (flagged when CISA lists them as exploited in the wild), end-of-life software, exposed `.git`, `.env`, backups and phpinfo pages in the web root, file permissions, nginx / Apache / IIS configuration, `wp-config.php` and TLS certificate files. Text, JSON or SARIF reports.

- **Read only.** It never modifies, deletes or fixes a file.
- **Nothing is sent by default.** No telemetry, no update check, no call home. Two explicit options use the network (`db update`, `--online`), described in [Network: what leaves the machine](#network-what-leaves-the-machine).
- **One static binary**, written in Go. No agent, no account, no service to install.

It complements [AttackScout](https://attackscout.com/en?utm_source=attackscout-agent&utm_medium=readme&utm_campaign=readme), which audits what the Internet sees of a domain. This tool is separate and free; it is not part of the AttackScout service.

## Contents

- [Install](#install-on-linux-macos-and-windows)
- [Quick start and example output](#quick-start-and-example-output)
- [What it checks](#what-it-checks)
- [Options and exit codes](#options-and-exit-codes)
- [Use it in CI](#use-it-in-ci)
- [Network: what leaves the machine](#network-what-leaves-the-machine)
- [FAQ](#faq)
- [Check your site from the outside too](#check-your-site-from-the-outside-too)
- [Limits](#limits)
- [Documentation](#documentation)

## Install on Linux, macOS and Windows

With Go 1.26 or later:

```sh
go install github.com/attackscout/attackscout-agent@latest
```

Prebuilt binaries for Linux, macOS and Windows (amd64 and arm64) are attached to each [GitHub release](https://github.com/AttackScout/attackscout-agent/releases), with a `checksums.txt` file. Archives are named `attackscout-agent_<version>_<os>_<arch>.tar.gz` (`.zip` on Windows).

Linux and macOS (replace the version and the architecture):

```sh
curl -LO https://github.com/AttackScout/attackscout-agent/releases/download/vX.Y.Z/attackscout-agent_X.Y.Z_linux_amd64.tar.gz
curl -LO https://github.com/AttackScout/attackscout-agent/releases/download/vX.Y.Z/checksums.txt
sha256sum --check --ignore-missing checksums.txt
tar -xzf attackscout-agent_X.Y.Z_linux_amd64.tar.gz
sudo install attackscout-agent /usr/local/bin/
```

Windows (PowerShell): download the `.zip` from the release page, check it against `checksums.txt` with `Get-FileHash -Algorithm SHA256`, extract it, and run `.\attackscout-agent.exe scan`.

Packages:

| Channel | Command |
|---|---|
| Homebrew | `brew install --cask attackscout/tap/attackscout-agent` |
| Scoop | `scoop bucket add attackscout https://github.com/AttackScout/scoop-bucket` then `scoop install attackscout-agent` |
| winget | `winget install AttackScout.AttackscoutAgent` |
| Docker | `docker run --rm -v "$PWD:/src:ro" ghcr.io/attackscout/attackscout-agent:0.2.0` |

Check the install with `attackscout-agent version`. Details: [install](docs/install.md).

## Quick start and example output

```sh
# automatic detection of the web root and of nginx / Apache
attackscout-agent scan

# explicit paths, French output, fail the job on high findings
attackscout-agent scan --root /var/www/site --nginx /etc/nginx --cert /etc/ssl/site.pem --lang fr --fail-on high

# JSON for scripts, SARIF for code scanning
attackscout-agent scan --root /var/www/site --format json --output report.json
attackscout-agent scan --root /var/www/site --format sarif --output report.sarif

# download the OSV, CISA KEV and endoflife.date data (network), then scan offline
attackscout-agent db update
attackscout-agent scan --root /var/www/site --project /srv/app
```

The real output below comes from running the tool on the fake WordPress site and the nginx configuration in `testdata/` of this repository, on a Windows machine (hence the "not applicable" line for permissions; on Linux they are checked). It is shortened: the list of findings is cut where marked.

```text
AttackScout agent 0.2.0 - local scan, read only
Network: nothing was sent
root: wordpress
nginx: nginx

Checks
  [fail          ] End of life - End-of-life table embedded in the binary, dated 2026-11-25
  [not checked   ] CVE (OSV) - CVEs not checked for 5 components that OSV does not track (WordPress, Joomla extensions, ...)
  [fail          ] Sensitive files
  [not applicable] File permissions - Not applicable on Windows: Unix permission bits do not exist there and ACLs are not read
  [fail          ] wp-config.php
  [fail          ] Web server configuration
  [fail          ] Certificates

Findings
  [CRITICAL] sensitive-env: Sensitive environment file in the web root: .env (content not read)
      wordpress/.env
      fix: Move the .env file outside the web root, then rotate every secret it contains
  [CRITICAL] wpconfig-salt-default: wp-config.php keys or salts empty or left at the default value: AUTH_KEY, SECURE_AUTH_KEY (values not shown)
      wordpress/wp-config.php
      fix: Generate new keys and salts (wp config shuffle-salts)
  [HIGH] php-eol: PHP 7.4 is end of life (branch 7.4, since 2022-11-28)
      configuration hint
      certainty: medium
      fix: Upgrade PHP to a supported branch: https://www.php.net/supported-versions.php
  [MEDIUM] header-hsts-missing: nginx configuration does not set Strict-Transport-Security
      nginx
      fix: Send Strict-Transport-Security: max-age=31536000; includeSubDomains on HTTPS (add_header Strict-Transport-Security "..." always;)
  [...]

Summary: 4 critical, 4 high, 5 medium, 10 low, 0 info
CISA KEV list not downloaded: run "attackscout-agent db update" to flag exploited vulnerabilities.

This scan sees the inside of the server. To see what the Internet sees, run the free external audit:
https://attackscout.com/en?utm_source=attackscout-agent&utm_medium=cli&utm_campaign=report
```

That closing link appears only in the text report; `--no-audit-link` hides it.

With `--fail-on high`, that same run exits with code `1`.

## What it checks

Every finding has a stable identifier, a severity (`info`, `low`, `medium`, `high`, `critical`), a short message and a fix. Each check reports one status: `pass`, `fail`, `not_applicable` or `not_checked`. A check that makes no sense on a system says `not_applicable`; a check that could not run says `not_checked`. Neither is ever shown as `pass`.

| Check | What it looks at | Guide |
|---|---|---|
| End of life | PHP, Node.js, .NET, nginx, Apache httpd, IIS, WordPress (core, plugins, themes), Drupal, Joomla, PrestaShop, React, Next.js, against [endoflife.date](https://endoflife.date) data (embedded, refreshed by `db update`) | [End-of-life software](docs/end-of-life-software.md) |
| Known vulnerabilities | `composer.lock`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`, `poetry.lock`, `Gemfile.lock`, `go.mod` / `go.sum`, `packages.lock.json`, `*.csproj`, `pom.xml`, dpkg / rpm / apk packages, Terraform providers, matched against [OSV](https://osv.dev), with CVSS severity, fixed version, advisory link and the [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) flag | [Known vulnerabilities (CVE)](docs/known-vulnerabilities-cve.md), [depth](docs/cve-scanning-depth.md) |
| Sensitive files | `.env`, `.git/`, SQL dumps and archives, `phpinfo.php`, logs, private keys, `.htpasswd`, `terraform.tfstate`... Names only, contents are never read | [Exposed files in the web root](docs/exposed-files-web-root.md) |
| phpinfo pages | PHP files calling `phpinfo()` under any name | [Exposed files in the web root](docs/exposed-files-web-root.md) |
| File permissions | World-writable files and directories, `777`, world-readable secrets, group-writable `wp-config.php` (Unix only) | [File permissions](docs/file-permissions.md) |
| Web server configuration | nginx, Apache and IIS: HSTS, CSP, X-Content-Type-Options, frame protection, Referrer-Policy, version disclosure, directory listing | [Security headers](docs/web-server-security-headers.md) |
| wp-config.php | Default or missing keys and salts, `WP_DEBUG`, `WP_DEBUG_DISPLAY`, `DISALLOW_FILE_EDIT`. Secret values are never printed | [wp-config.php security](docs/wordpress-wp-config-security.md) |
| Certificates | Local PEM files: expiry, expiring in less than 30 days, expired chain, weak key, SHA-1 or MD5 signature | [Certificate check](docs/ssl-certificate-check.md) |

It reads certificate **files** on disk. It does not open a connection to your site, so it does not test the TLS protocol versions or cipher suites a visitor negotiates.

## Options and exit codes

| Flag | Meaning |
|---|---|
| `--root DIR` | Web root. Default: from the nginx / Apache configuration, then `/var/www/html`, `/srv/www`, `/usr/share/nginx/html`, `/var/www` (`C:\inetpub\wwwroot` on Windows), then the current directory if it looks like a site |
| `--project DIR` | Extra directory with lockfiles or Terraform files (repeatable) |
| `--nginx DIR` | nginx configuration. Default: `/etc/nginx`, `/usr/local/etc/nginx`, `/opt/homebrew/etc/nginx` (`C:\nginx\conf`) |
| `--apache DIR` | Apache configuration. Default: `/etc/apache2`, `/etc/httpd`, `/usr/local/etc/httpd`, `/opt/homebrew/etc/httpd` (`C:\Apache24\conf`) |
| `--cert FILE` | PEM certificate to check (repeatable). Certificates named in the nginx / Apache configuration are added |
| `--format F` | `text` (default), `json` or `sarif` |
| `--json` | Same as `--format json` |
| `--output FILE` | Write the report to a file |
| `--fail-on SEV` | Exit with code 1 when a finding is at least `critical`, `high`, `medium`, `low` or `info`. Default `none` |
| `--no-audit-link` | Hide the link to the free external audit at the end of the text report |
| `--sysroot DIR` | Where to read the dpkg, rpm and apk databases. Default `/` |
| `--lang en\|fr` | Report language. Default `en` |
| `--online` | Look up CVEs with api.osv.dev instead of the local database |
| `--db DIR` | Database directory (OSV, CISA KEV, endoflife.date). Default: user cache directory + `attackscout-agent` |

Commands: `scan`, `db update` (`--db`, `--ecosystems`; default npm, Packagist, PyPI, NuGet, Go, RubyGems, Maven and the ecosystem of the system), `version`, `help`.

Exit codes: `0` success, `1` a finding reached `--fail-on` (or `db update` failed for a source), `2` usage error. Full reference: [command line](docs/command-line-reference.md).

## Use it in CI

Ready-made integrations write a SARIF report (one alert per CVE, with CVSS severity, fixed version, advisory link and the CISA KEV flag) and fail the job at the threshold you choose:

```yaml
# .github/workflows/attackscout-agent.yml
name: attackscout-agent
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: AttackScout/attackscout-agent@v0.2.0
        with:
          fail-on: high
```

| Platform | How | Guide |
|---|---|---|
| GitHub Actions | `uses: AttackScout/attackscout-agent@v0.2.0`, alerts in the Security tab | [GitHub Actions](docs/github-actions.md) |
| GitLab CI | `include:` `ci/gitlab/attackscout-agent.gitlab-ci.yml`, SARIF and JSON artifacts | [GitLab CI](docs/gitlab-ci.md) |
| Azure DevOps | `ci/azure-devops/attackscout-agent.yml` template or the `AttackScoutAgent@0` task | [Azure DevOps](docs/azure-devops.md) |
| Anything else | `attackscout-agent scan --format sarif --output results.sarif --fail-on high` | [Use in CI](docs/ci-integration.md) |

On a server, the same command works from cron or a deployment hook.

## Network: what leaves the machine

**By default, nothing.** No HTTP call, no telemetry, no update check. The scan reads local files, runs a few local commands if they exist (`php -v`, `node --version`, `dotnet --list-runtimes`, `nginx -v`, `apache2 -v` / `httpd -v`, `terraform version`, `tofu version`; `reg query` for IIS on Windows), and writes nothing.

Two explicit commands use the network, and only them:

- `attackscout-agent db update` downloads the OSV archives (`all.zip`) of each ecosystem from `https://osv-vulnerabilities.storage.googleapis.com`, the CISA KEV list from `https://www.cisa.gov` and the endoflife.date data from `https://endoflife.date`, into the user cache directory (`--db` to change it). Nothing about your server is sent.
- `attackscout-agent scan --online` sends to `https://api.osv.dev` the **name, version and ecosystem** of each package, then fetches the details of the matching vulnerabilities by their identifiers. No path, file name, host name or domain name is sent. Local npm packages (`file:` links) are not sent.

Without a local database and without `--online`, the report says "CVEs not checked" instead of claiming there is no CVE.

How this is guaranteed: `nonetwork_test.go` parses every source file and only `internal/vulns` may import a networking package; `TestDefaultScanUsesNoNetwork` runs a full default scan with a guard on `http.DefaultTransport` and fails on any request. Details: [network and offline use](docs/offline-and-network.md).

## FAQ

### How do I check my website security from the server?

Install `attackscout-agent` on the server and run `attackscout-agent scan`. It detects the web root and the nginx or Apache configuration, then reports end-of-life software, exposed files, risky permissions, missing security headers and certificate problems, each with a fix.

### Is there a free, open source, self-hosted security audit tool for a web server?

This one is MIT-licensed, free, and runs locally with no account. It checks the server side only; to see what visitors and scanners see, use an external scan too (see below).

### Does it send my data anywhere?

Not by default. The default scan makes no network request, and a test fails if it does. `db update` downloads public vulnerability data and sends nothing about your server. `--online` sends package names, versions and ecosystems to api.osv.dev, nothing else.

### How do I check for exposed .env, .git or backup files in the web root?

`scan` walks the web root (ten levels deep, `node_modules` and `vendor` skipped) and reports `.env`, `.git/`, SQL dumps, archives, `phpinfo.php`, logs and private keys by name. It never opens their contents. See [exposed files](docs/exposed-files-web-root.md).

### How do I check security headers (HSTS, CSP) in nginx or Apache?

`scan` reads your nginx, Apache and IIS configuration files and reports headers that are not set. It reads the configuration, it does not request your site, so a header added by a proxy or CDN in front of the server is not seen. See [security headers](docs/web-server-security-headers.md).

### Can it check the TLS certificate of my server?

It checks PEM certificate files: those you pass with `--cert` and those named by `ssl_certificate` or `SSLCertificateFile`. It reports expiry, a certificate expiring in under 30 days, an expired chain, weak keys and SHA-1 or MD5 signatures. It does not connect to the site. See [certificate check](docs/ssl-certificate-check.md).

### Can I use it in a CI pipeline?

Yes. There is a GitHub Action with SARIF upload to code scanning, a GitLab CI template and an Azure DevOps template and task. Use `--fail-on high` (or another severity) and the job fails with exit code `1`. See [use in CI](docs/ci-integration.md).

### Does it work on Windows?

Yes. It runs on Windows and checks IIS `web.config`, nginx and Apache. File permissions are reported as `not_applicable` there, because Unix permission bits do not exist on Windows and ACLs are not read.

## Check your site from the outside too

This tool sees the inside of your server. It cannot see what a visitor or a scanner sees: the headers your proxy or CDN actually sends, what is reachable from the Internet, or the certificate actually served. For that, run the external audit of your domain at [attackscout.com/en](https://attackscout.com/en?utm_source=attackscout-agent&utm_medium=readme&utm_campaign=readme).

## Limits

- Version comparison is done by osv-scalibr: SemVer for npm, Composer rules for Packagist, PEP 440 for PyPI, NuGet and Go rules. Composer branch names (`dev-main`) cannot be compared.
- A constraint (`requests>=2.20`, `.csproj` reference, Terraform `~> 5.0`) is replaced by its smallest version: certainty `medium`.
- `vendor/composer/installed.json` is not read: `composer.lock` is.
- OSV does not cover WordPress plugins and themes, Joomla extensions or the PHP, nginx and Apache version numbers: those are checked for end of life only, and reported as "CVEs not checked". Distribution builds of PHP, nginx and Apache are matched through their dpkg / rpm / apk package.
- `pom.xml` versions set through properties or parent POMs are skipped: no network resolution is done.
- Terraform and OpenTofu: versions are listed, the configuration is not analysed. [tfsec](https://github.com/aquasecurity/tfsec) and [Checkov](https://github.com/bridgecrewio/checkov) do that.
- Without `db update`, the end-of-life table is as fresh as the release you run.
- Permissions are not checked on Windows.

## Documentation

[Index](docs/index.md): [install](docs/install.md), [end-of-life software](docs/end-of-life-software.md), [known vulnerabilities](docs/known-vulnerabilities-cve.md), [CVE depth](docs/cve-scanning-depth.md), [GitHub Actions](docs/github-actions.md), [GitLab CI](docs/gitlab-ci.md), [Azure DevOps](docs/azure-devops.md), [exposed files](docs/exposed-files-web-root.md), [file permissions](docs/file-permissions.md), [security headers](docs/web-server-security-headers.md), [wp-config.php](docs/wordpress-wp-config-security.md), [certificates](docs/ssl-certificate-check.md), [CI](docs/ci-integration.md), [network and offline use](docs/offline-and-network.md), [command line](docs/command-line-reference.md).

## Development

```sh
go test ./...
go vet ./...
```

Fixtures live in `testdata/` (fake WordPress, Drupal, Joomla and PrestaShop sites, nginx, Apache and IIS configurations, lockfiles, Terraform files). Tests never use the network: `db update` and `--online` are tested against local `httptest` servers.

## License

MIT, see [LICENSE](LICENSE). Third-party components are listed in [NOTICE](NOTICE): osv-scalibr and the OSV bindings are under the Apache License 2.0, which is compatible with the MIT license of this tool.
