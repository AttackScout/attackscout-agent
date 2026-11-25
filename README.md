# attackscout-cli

[Français](README.fr.md)

Free, open source command-line tool that checks a website **from inside its server**: outdated and end-of-life software, known CVEs, exposed files, file permissions, web server headers, `wp-config.php` and certificates.

It only reads. It never modifies, deletes or fixes a file, and it sends **nothing** over the network unless you ask for it (`db update`, `--online`).

It complements [AttackScout](https://attackscout.com/?utm_source=cli&utm_medium=cli&utm_campaign=attackscout-cli), which audits what the Internet sees of a domain. This tool is separate and free; it is not part of the AttackScout service.

## Install

```sh
go install github.com/attackscout/attackscout-cli@latest
```

Prebuilt binaries for Linux, macOS and Windows (amd64 and arm64) are attached to each [GitHub release](https://github.com/attackscout/attackscout-cli/releases), with a `checksums.txt` file. Homebrew: coming soon.

Requires Go 1.26 or later to build from source.

## Usage

```sh
# scan with automatic detection of the web root and of nginx / Apache
attackscout-cli scan

# explicit paths, French output, fail the CI job on high findings
attackscout-cli scan --root /var/www/site --nginx /etc/nginx --cert /etc/ssl/site.pem --lang fr --fail-on high

# JSON for scripts
attackscout-cli scan --root /var/www/site --json > report.json

# download the OSV vulnerability databases once (network), then scan offline
attackscout-cli db update
attackscout-cli scan --root /var/www/site --project /srv/app --project /srv/infra
```

| Flag | Meaning |
|---|---|
| `--root DIR` | Web root. Default: from the nginx / Apache configuration, then `/var/www/html`, `/srv/www`, `/usr/share/nginx/html`, `/var/www` (`C:\inetpub\wwwroot` on Windows), then the current directory if it looks like a site |
| `--project DIR` | Extra directory with lockfiles or Terraform files (repeatable) |
| `--nginx DIR` | nginx configuration. Default: `/etc/nginx`, `/usr/local/etc/nginx`, `/opt/homebrew/etc/nginx` (`C:\nginx\conf`) |
| `--apache DIR` | Apache configuration. Default: `/etc/apache2`, `/etc/httpd`, `/usr/local/etc/httpd`, `/opt/homebrew/etc/httpd` (`C:\Apache24\conf`) |
| `--cert FILE` | PEM certificate to check (repeatable). Certificates named in the nginx / Apache configuration are added |
| `--json` | JSON output instead of text |
| `--fail-on SEV` | Exit with code 1 when a finding is at least `info`, `low`, `medium`, `high` or `critical`. Default `none` |
| `--lang en\|fr` | Report language. Default `en` |
| `--online` | Look up CVEs with api.osv.dev instead of the local database (see below) |
| `--db DIR` | OSV database directory. Default: user cache directory + `attackscout-cli` |

Exit codes: `0` success, `1` a finding reached `--fail-on` (or `db update` failed for an ecosystem), `2` usage error.

Every report ends with a link to the free external audit: <https://attackscout.com/?utm_source=cli&utm_medium=cli&utm_campaign=attackscout-cli>.

## Check statuses

Each check reports one status: `pass`, `fail`, `not_applicable` or `not_checked`. A check that makes no sense on a system says `not_applicable`, never `pass`. A check that could not run (no web root, no configuration, no vulnerability database) says `not_checked`, never `pass`.

## Checks

Every finding has a stable identifier, a severity (`info`, `low`, `medium`, `high`, `critical`), a short message and a fix.

### 1. Versions and end of life (`end-of-life`)

| What | Where the version comes from |
|---|---|
| PHP | `php -v`, else configuration hints (`php8.1-fpm` sockets, `/etc/php/X.Y`) |
| Node.js | `node --version`, else `.nvmrc` / `.node-version` |
| .NET | `dotnet --list-runtimes`, else `<TargetFramework>` in `.csproj` files |
| WordPress | `wp-includes/version.php`, plugins (plugin headers), themes (`style.css`) |
| Drupal | `core/lib/Drupal.php` or `includes/bootstrap.inc`, contrib modules and themes (`*.info.yml`) |
| Joomla | `administrator/manifests/files/joomla.xml`, components, modules, plugins, templates (XML manifests) |
| PrestaShop | `app/AppKernel.php` or `config/settings.inc.php` |
| React, Next.js | lockfiles, else `node_modules/react/package.json` and `node_modules/next/package.json` |

IDs: `<product>-eol` (high), `<product>-eol-soon` (medium, less than 90 days), `<product>-patch-behind` (low), `<product>-version` (info).

The end-of-life table is **embedded in the binary** (`go:embed`) and carries its date (`internal/eol/data.json`, printed in every report). It is based on endoflife.date (MIT) and vendor pages; a vendor date wins when it is earlier. A new release of the tool brings a new table.

### 2. Known vulnerabilities (`vulnerabilities`)

The inventory is matched against the [OSV](https://osv.dev) database with Google's [osv-scalibr](https://github.com/google/osv-scalibr) library (Apache-2.0, version pinned in `go.mod`). Lockfiles are parsed by the osv-scalibr extractors:

| Ecosystem | Files |
|---|---|
| npm | `package-lock.json`, `yarn.lock` (v1 and Berry), `pnpm-lock.yaml` |
| Composer (Packagist) | `composer.lock` |
| PyPI | `requirements.txt` |
| NuGet | `packages.lock.json`, `packages.config`, `*.csproj` |
| Go | Terraform and OpenTofu providers and binaries (see below) |

Each CVE comes with:

- **risk**: the CVSS v3.x base score computed from the vector, mapped to a severity (9.0+ critical, 7.0+ high, 4.0+ medium, else low). Without a v3 vector, the severity given by the advisory database is used; malicious packages (`MAL-`) are critical;
- **certainty**: `high` when the exact version was read (lockfile, version header, command output), `medium` when it was deduced (a constraint such as `requests>=2.20`, a `.csproj` reference, a configuration hint);
- **fix**: the smallest fixed version above the installed one (OSV `fixed` event), in plain words: "Upgrade lodash to 4.17.21 or later".

Components that OSV does not track (WordPress core, plugins and themes, Joomla extensions, Drupal 7 modules) are listed with "CVEs not checked", never "no CVE".

ID: `vulnerable-component`.

#### Terraform and OpenTofu (inventory only)

The tool lists versions, it does not analyse the configuration:

- providers from `.terraform.lock.hcl` (exact version, certainty high) and from `required_providers` blocks in `.tf` files (smallest version allowed by the constraint, certainty medium);
- Terraform from `required_version`, `.terraform-version` or `terraform version`; OpenTofu from `.opentofu-version` or `tofu version`.

They are looked up in the OSV Go ecosystem: `github.com/<namespace>/terraform-provider-<name>`, `github.com/hashicorp/terraform`, `github.com/opentofu/opentofu`. When OSV does not know a module, the report says "CVEs not checked".

### 3. Sensitive files in the web root (`sensitive-files`)

Only names are read; contents are never opened or printed.

`sensitive-env` (`.env`, `.env.*`, critical), `sensitive-env-sample` (low), `sensitive-vcs` (`.git/`, `.svn/`, `.hg/`, `.bzr/`, high), `sensitive-backup` (`.sql`, `.zip`, `.tar.gz`, `.tgz`, `.7z`, `.rar`, `.bak`, `.old`, `.orig`, `.swp`, `~`...; critical for database dumps and `wp-config` / `.env` copies), `sensitive-phpinfo` (`phpinfo.php`, `info.php`), `sensitive-ds-store`, `sensitive-composer` (`composer.json` / `composer.lock` at the root), `sensitive-auth-json`, `sensitive-log`, `sensitive-htpasswd`, `sensitive-private-key` (`.key`, `.pem`, `.p12`, `id_rsa`...), `sensitive-tfstate`.

### 4. File permissions (`permissions`)

`perm-file-world-writable`, `perm-dir-777`, `perm-dir-world-writable` (without sticky bit), `perm-secret-world-readable` (`wp-config.php`, `.env`, `settings.php`, `configuration.php`, `auth.json`...). On Windows the check is `not_applicable`: Unix permission bits do not exist there, and ACLs are not read.

### 5. Web server configuration (`web-server`)

nginx (enabled sites only), Apache (plus `.htaccess` of the web root) and IIS (`web.config` of the web root, read with `encoding/xml`; if it cannot be parsed the IIS part is `not_checked`).

`header-hsts-missing` (medium), `header-csp-missing`, `header-xcto-missing`, `header-frame-missing` (X-Frame-Options or CSP `frame-ancestors`), `header-referrer-missing`, `server-tokens` (`server_tokens`, `ServerTokens`, IIS `removeServerHeader`), `server-signature` (`ServerSignature`), `x-powered-by` (IIS), `directory-listing` (`autoindex on`, `Options Indexes`, `directoryBrowse`).

### 6. wp-config.php (`wp-config`)

`wpconfig-salt-default` (keys or salts empty or "put your unique phrase here", critical), `wpconfig-salt-missing` (high), `wpconfig-debug`, `wpconfig-debug-display` (`WP_DEBUG_DISPLAY` true, or `WP_DEBUG` true without it), `wpconfig-file-edit` (`DISALLOW_FILE_EDIT` absent). Secret values are never printed. `wp-config.php` is also looked for one level above the web root, as WordPress allows.

### 7. Certificates (`certificates`)

PEM files from `--cert` and from `ssl_certificate` / `SSLCertificateFile`: `cert-expired` (critical), `cert-expiring` (less than 30 days, high), `cert-chain-expired`, `cert-weak-key` (RSA under 2048 bits, ECDSA under 256, DSA), `cert-weak-signature` (MD5, SHA-1), `cert-valid` (info). Private keys in the same file are skipped and never printed.

## Network: what leaves the machine

**By default, nothing.** No HTTP call, no telemetry, no update check. The scan reads local files, runs a few local commands if they exist (`php -v`, `node --version`, `dotnet --list-runtimes`, `terraform version`, `tofu version`), and writes nothing.

Two explicit commands use the network, and only them:

- `attackscout-cli db update` downloads the OSV archives (`all.zip`) of npm, Packagist, PyPI, NuGet and Go from `https://osv-vulnerabilities.storage.googleapis.com`, with the osv-scalibr download mechanism, into the user cache directory (`--db` to change it). Nothing about your server is sent. Pick ecosystems with `--ecosystems npm,Packagist`.
- `attackscout-cli scan --online` sends to `https://api.osv.dev` (`/v1/querybatch`) the **name, version and ecosystem** of each package, then fetches the details of the matching vulnerabilities by their identifiers (`/v1/vulns/<id>`). No path, file name, host name or domain name is sent. This is what the osv-scalibr `osvdev` enricher sends (`pkgToQuery`), and a test checks it. Local npm packages (`file:` links) are not sent.

Without a local database and without `--online`, the report says "CVEs not checked: run attackscout-cli db update" instead of claiming there is no CVE.

How it is guaranteed:

- `nonetwork_test.go` parses every source file: only `internal/vulns` may import a networking package, and its network functions are called only by `onlineMatcher` (`--online`) and `runDBUpdate` (`db update`);
- `internal/cli.TestDefaultScanUsesNoNetwork` replaces `http.DefaultTransport` with a guard that counts every request, runs a full default scan with a local database, and fails on any request;
- on the default path, osv-scalibr receives an HTTP client that refuses every request.

## Limits

- Version comparison is done by osv-scalibr: SemVer for npm, Composer rules for Packagist, PEP 440 for PyPI, NuGet and Go rules. Composer branch names (`dev-main`) cannot be compared.
- A constraint (`requests>=2.20`, `.csproj` reference, Terraform `~> 5.0`) is replaced by its smallest version: certainty medium, results may differ from what is installed.
- `vendor/composer/installed.json` is not read: `composer.lock` is.
- OSV does not cover WordPress, Joomla extensions or PHP itself: those versions are checked for end of life only.
- The end-of-life table is as fresh as the release you run.
- Permissions are not checked on Windows.

## Ideas, not in this version

- Terraform configuration analysis: [tfsec](https://github.com/aquasecurity/tfsec) and [Checkov](https://github.com/bridgecrewio/checkov) already do it well. This tool only lists Terraform versions.
- Homebrew tap.

## Development

```sh
go test ./...
go vet ./...
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0 run ./...
```

Fixtures live in `testdata/` (fake WordPress, Drupal, Joomla and PrestaShop sites, nginx, Apache and IIS configurations, lockfiles, Terraform files) and `internal/vulns/testdata/` (OSV records). Certificates are generated during the tests. Tests never use the network: `db update` and `--online` are tested against local `httptest` servers.

## License

MIT, see [LICENSE](LICENSE). Third-party components are listed in [NOTICE](NOTICE): osv-scalibr and the OSV bindings are under the Apache License 2.0, which is compatible with the MIT license of this tool.

---

This tool sees the inside of your server. To see what the Internet sees, run the free external audit: <https://attackscout.com/?utm_source=cli&utm_medium=cli&utm_campaign=attackscout-cli>
