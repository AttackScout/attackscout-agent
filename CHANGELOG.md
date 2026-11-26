# Changelog

## 0.2.0 - 2026-11-26

### Added

- CVE depth: `poetry.lock`, `Gemfile.lock`, `go.mod` and `go.sum`, `pom.xml` (Maven), and the system packages of dpkg, rpm and apk (Debian, Ubuntu, Alpine, Red Hat, Rocky Linux, AlmaLinux, SUSE), on top of the npm, Yarn, pnpm, Composer, pip and NuGet files.
- nginx, Apache httpd and IIS versions, checked for end of life.
- CISA Known Exploited Vulnerabilities: a CVE exploited in the wild becomes critical, with the date it was added and its ransomware use; the text summary counts them.
- endoflife.date data downloaded by `db update`, used instead of the embedded table when present.
- Advisory link (`osv.dev/vulnerability/<id>`) on every vulnerability.
- `phpinfo-exposed`: PHP files that call `phpinfo()` under any name.
- `perm-wpconfig-group-writable`: `wp-config.php` writable by its group.
- `--format text|json|sarif`, `--output FILE`, `--no-audit-link`, `--sysroot DIR`.
- SARIF 2.1.0 output with `security-severity`, fixed version and KEV flag, for GitHub code scanning, GitLab and Azure DevOps.
- GitHub Action (`action.yml`), GitLab CI template, Azure Pipelines template and Azure DevOps task.
- Packages: Homebrew cask, Scoop manifest, Docker image on ghcr.io, winget manifests.
- Documentation: one page per CI integration, the depth of the CVE scan, installation.

### Changed

- `db update` downloads the OSV archives directly (skipped when the checksum is unchanged), plus the CISA KEV list and the endoflife.date data. Default ecosystems: npm, Packagist, PyPI, NuGet, Go, RubyGems, Maven and the ecosystem of the system.
- The link to the free external audit points to `attackscout.com/en`, appears only at the end of the text report, and is no longer in the JSON report or the usage text.
- `--json` is kept as a shortcut for `--format json`.

## 0.1.0

- First release: end of life, CVEs (OSV) in lockfiles, sensitive files, permissions, web server headers, `wp-config.php` and certificates. Read only, no network by default.
