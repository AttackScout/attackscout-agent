# Use attackscout-agent in CI to fail a pipeline on security findings

`--fail-on` turns the report into a gate. The command exits with code `1` when at least one finding is at the given severity or above, and `0` otherwise.

```sh
attackscout-agent scan --root . --project . --fail-on high
```

Severities, from lowest: `info`, `low`, `medium`, `high`, `critical`. The default is `none`: the command never fails because of findings.

## GitHub Actions

```yaml
name: security-check
on: [push]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.26"
      - run: go install github.com/attackscout/attackscout-agent@latest
      - run: attackscout-agent db update
      - run: attackscout-agent scan --root . --project . --json > report.json
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-report
          path: report.json
      - run: attackscout-agent scan --root . --project . --fail-on high
```

## GitLab CI

```yaml
security-check:
  image: golang:1.26
  script:
    - go install github.com/attackscout/attackscout-agent@latest
    - export PATH="$PATH:$(go env GOPATH)/bin"
    - attackscout-agent db update
    - attackscout-agent scan --root . --project . --fail-on high
```

## Cron on a server

```sh
0 6 * * 1 attackscout-agent scan --json > /var/log/attackscout-agent.json
```

## Notes

- A CI runner sees the checked-out project, not your production server. In CI it is most useful for lockfiles and Terraform files (`--project`); the file and configuration checks need the real web root and configuration, so run those on the server.
- `attackscout-agent db update` is the only step that needs the network. Keep the database directory (`--db DIR`) between runs to avoid downloading it each time. See [network and offline use](offline-and-network.md).
- Exit code `2` means a usage error (unknown flag, unknown language, unknown severity).
- `--json` gives a structure with `checks`, `findings` and `components` for scripts.

---

## Check your site from the outside too

attackscout-agent sees the inside of your server. To see what the Internet sees of your domain, run the external audit at [attackscout.com/en](https://attackscout.com/en?utm_source=cli&utm_medium=docs&utm_campaign=attackscout-agent).

[Documentation index](index.md) | [Command line](command-line-reference.md) | [Network](offline-and-network.md) | [Known vulnerabilities](known-vulnerabilities-cve.md)
