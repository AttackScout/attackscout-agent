# GitHub Actions: scan a website repository for CVEs and upload SARIF to code scanning

The `AttackScout/attackscout-agent` action installs the released binary (checked against `checksums.txt`), downloads the OSV, CISA KEV and endoflife.date data, scans the repository offline and uploads a SARIF report to the **Security > Code scanning** tab. Each CVE becomes an alert with its CVSS-based `security-severity`, the fixed version and a link to the advisory; vulnerabilities exploited in the wild (CISA KEV) are raised to critical.

## Minimal workflow

```yaml
# .github/workflows/attackscout-agent.yml
name: attackscout-agent
on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: "17 5 * * 1"   # weekly: new CVEs appear without code changes

permissions:
  contents: read
  security-events: write   # upload the SARIF report

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: AttackScout/attackscout-agent@v0.2.0
        with:
          fail-on: high
```

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `version` | `latest` | Release to install, for example `0.2.0` |
| `path` | `.` | Directory scanned as web root and project |
| `args` | | Extra `scan` arguments, for example `--nginx deploy/nginx --lang fr` |
| `fail-on` | `high` | `critical`, `high`, `medium`, `low`, `info` or `none` |
| `db-update` | `true` | Download the databases before the scan |
| `ecosystems` | | OSV ecosystems to download, comma-separated; empty for the defaults |
| `upload-sarif` | `true` | Upload to code scanning (needs `security-events: write`) |
| `sarif-file` | `attackscout-agent.sarif` | Path of the report |
| `category` | `attackscout-agent` | Code scanning category |

Outputs: `sarif-file` and `exit-code`.

The SARIF report is uploaded even when the threshold fails the job, so the alerts are always visible. Private repositories need GitHub Advanced Security (or GitHub Code Security) for code scanning; set `upload-sarif: false` otherwise and keep the report with `actions/upload-artifact`.

## Without the action

```yaml
      - run: |
          curl -fsSLO https://github.com/AttackScout/attackscout-agent/releases/download/v0.2.0/attackscout-agent_0.2.0_linux_amd64.tar.gz
          tar -xzf attackscout-agent_0.2.0_linux_amd64.tar.gz
          ./attackscout-agent db update
          ./attackscout-agent scan --root . --project . --format sarif --output results.sarif || true
          ./attackscout-agent scan --root . --project . --fail-on high
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

## Which alerts appear

Every finding of severity `low` and above: CVEs in lockfiles (npm, Composer, PyPI, Poetry, RubyGems, Go, NuGet, Maven), end-of-life runtimes and CMS, `.env`, `.git` and backups committed in the web root, phpinfo pages, `wp-config.php` settings and nginx / Apache / IIS configuration. `info` findings (detected versions) stay in the text and JSON reports. See [how deep the CVE scan goes](cve-scanning-depth.md).

---

## Check your site from the outside too

The repository is only half of the picture. To see what the Internet sees of your domain, run the free external audit at [attackscout.com/en](https://attackscout.com/en?utm_source=attackscout-agent&utm_medium=docs&utm_campaign=github-actions).

[Documentation index](index.md) | [GitLab CI](gitlab-ci.md) | [Azure DevOps](azure-devops.md) | [Use in CI](ci-integration.md)
