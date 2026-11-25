# What attackscout-agent sends over the network, and how to run it offline

**By default, nothing.** No HTTP call, no telemetry, no update check. The scan reads local files, runs a few local commands if they exist (`php -v`, `node --version`, `dotnet --list-runtimes`, `terraform version`, `tofu version`), and writes nothing.

## The two commands that use the network

| Command | Contacts | Sends |
|---|---|---|
| `attackscout-agent db update` | `osv-vulnerabilities.storage.googleapis.com` | Nothing about your server: it downloads the public OSV archives (`all.zip`) of npm, Packagist, PyPI, NuGet and Go into the user cache directory |
| `attackscout-agent scan --online` | `api.osv.dev` | The name, version and ecosystem of each package, then the identifiers of matching vulnerabilities. No path, file name, host name or domain name. Local npm packages (`file:` links) are not sent |

## Offline workflow

1. On a machine with network access: `attackscout-agent db update --db ./osv`
2. Copy the `osv` directory to the server.
3. On the server: `attackscout-agent scan --db ./osv --root /var/www/site`

Pick ecosystems with `--ecosystems npm,Packagist`. Without a database and without `--online`, the report says "CVEs not checked".

## How the guarantee is enforced

- `nonetwork_test.go` parses every source file: only `internal/vulns` may import a networking package, and its network functions are called only by the `--online` matcher and `db update`.
- `TestDefaultScanUsesNoNetwork` replaces `http.DefaultTransport` with a guard that counts requests, runs a full default scan with a local database, and fails on any request.
- On the default path, osv-scalibr receives an HTTP client that refuses every request.

You can read the tests in the repository and check this yourself. See also [known vulnerabilities](known-vulnerabilities-cve.md).

---

## Check your site from the outside too

attackscout-agent sees the inside of your server. To see what the Internet sees of your domain, run the external audit at [attackscout.com/en](https://attackscout.com/en?utm_source=cli&utm_medium=docs&utm_campaign=attackscout-agent).

[Documentation index](index.md) | [Known vulnerabilities](known-vulnerabilities-cve.md) | [CI](ci-integration.md) | [Command line](command-line-reference.md)
