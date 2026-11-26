# Use attackscout-agent in CI to fail a pipeline on security findings

`--fail-on` turns the report into a gate. The command exits with code `1` when at least one finding is at the given severity or above, and `0` otherwise.

```sh
attackscout-agent scan --root . --project . --fail-on high
```

Severities, from lowest: `info`, `low`, `medium`, `high`, `critical`. The default is `none`: the command never fails because of findings.

Ready-made integrations, with SARIF reports:

- [GitHub Actions](github-actions.md): `uses: AttackScout/attackscout-agent@v0.2.0`, alerts in the Security tab.
- [GitLab CI](gitlab-ci.md): `include:` the template, SARIF and JSON artifacts.
- [Azure DevOps](azure-devops.md): YAML template or the `AttackScoutAgent@0` task, Scans tab.

## GitHub Actions

```yaml
name: security-check
on: [push]
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

## GitLab CI

```yaml
include:
  - remote: https://raw.githubusercontent.com/AttackScout/attackscout-agent/v0.2.0/ci/gitlab/attackscout-agent.gitlab-ci.yml
```

## Azure Pipelines

```yaml
steps:
  - checkout: self
  - template: ci/attackscout-agent.yml   # copied from ci/azure-devops/
    parameters:
      failOn: high
```

## Cron on a server

```sh
0 6 * * 1 attackscout-agent scan --json > /var/log/attackscout-agent.json
```

## Notes

- A CI runner sees the checked-out project, not your production server. In CI it is most useful for lockfiles and Terraform files (`--project`); the file and configuration checks need the real web root and configuration, so run those on the server.
- `attackscout-agent db update` is the only step that needs the network. Keep the database directory (`--db DIR`) between runs to avoid downloading it each time. See [network and offline use](offline-and-network.md).
- Exit code `2` means a usage error (unknown flag, unknown language, unknown severity).
- `--format json` gives a structure with `checks`, `findings` and `components` for scripts; `--format sarif --output results.sarif` feeds code scanning tools.
- `--no-audit-link` removes the closing link of the text report from CI logs.

---

## Check your site from the outside too

attackscout-agent sees the inside of your server. To see what the Internet sees of your domain, run the free external audit at [attackscout.com/en](https://attackscout.com/en?utm_source=attackscout-agent&utm_medium=docs&utm_campaign=docs).

[Documentation index](index.md) | [Command line](command-line-reference.md) | [Network](offline-and-network.md) | [Known vulnerabilities](known-vulnerabilities-cve.md)
