# GitLab CI: CVE and website security scan with a SARIF report

`ci/gitlab/attackscout-agent.gitlab-ci.yml` is a ready-to-include job. It runs in the `ghcr.io/attackscout/attackscout-agent` image, caches the OSV, CISA KEV and endoflife.date data between pipelines, and keeps a SARIF and a JSON report as artifacts. The text report is printed in the job log and the job fails at the threshold you choose.

## Include the template

```yaml
# .gitlab-ci.yml
include:
  - remote: https://raw.githubusercontent.com/AttackScout/attackscout-agent/v0.2.0/ci/gitlab/attackscout-agent.gitlab-ci.yml

attackscout-agent:
  variables:
    ATTACKSCOUT_FAIL_ON: high
```

Run it on a schedule too (CI/CD > Schedules): new CVEs are published every day, without any change in your code.

## Variables

| Variable | Default | Meaning |
|---|---|---|
| `ATTACKSCOUT_VERSION` | `0.2.0` | Image tag |
| `ATTACKSCOUT_PATH` | `.` | Directory scanned as web root and project |
| `ATTACKSCOUT_FAIL_ON` | `high` | `critical`, `high`, `medium`, `low`, `info` or `none` |
| `ATTACKSCOUT_ARGS` | | Extra `scan` arguments |
| `ATTACKSCOUT_DB_UPDATE` | `true` | Download the databases before the scan |
| `ATTACKSCOUT_ECOSYSTEMS` | | OSV ecosystems to download; empty for the defaults |

## Reports

- `gl-attackscout-agent.sarif`: SARIF 2.1.0, one rule per CVE with its CVSS-based `security-severity`, the fixed version and the advisory link.
- `attackscout-agent.json`: every component, check and finding, with the `known_exploited` flag of the CISA KEV list.

Both are kept 30 days. GitLab shows SARIF in the security widgets only on some tiers; on the others, open the artifact or convert it.

## Without the image

On a shell runner, download the release archive and run the same commands:

```yaml
attackscout-agent:
  script:
    - curl -fsSLO https://github.com/AttackScout/attackscout-agent/releases/download/v0.2.0/attackscout-agent_0.2.0_linux_amd64.tar.gz
    - tar -xzf attackscout-agent_0.2.0_linux_amd64.tar.gz
    - ./attackscout-agent db update
    - ./attackscout-agent scan --root . --project . --fail-on high --no-audit-link
```

What is scanned: [how deep the CVE scan goes](cve-scanning-depth.md).

---

## Check your site from the outside too

To see what the Internet sees of your domain, run the free external audit at [attackscout.com/en](https://attackscout.com/en?utm_source=attackscout-agent&utm_medium=docs&utm_campaign=gitlab-ci).

[Documentation index](index.md) | [GitHub Actions](github-actions.md) | [Azure DevOps](azure-devops.md) | [Use in CI](ci-integration.md)
