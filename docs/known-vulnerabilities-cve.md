# Find known vulnerabilities (CVE) in npm, Composer, PyPI, NuGet and Go dependencies on your server

`attackscout-agent` matches the dependencies it finds on the server against the [OSV](https://osv.dev) vulnerability database, with Google's [osv-scalibr](https://github.com/google/osv-scalibr) library (Apache-2.0).

```sh
attackscout-agent db update                      # once, needs network
attackscout-agent scan --root /var/www/site --project /srv/app
```

Without a local database and without `--online`, the report says "CVEs not checked" and never claims there is no CVE.

## Supported lockfiles

| Ecosystem | Files |
|---|---|
| npm | `package-lock.json`, `yarn.lock` (v1 and Berry), `pnpm-lock.yaml` |
| Composer (Packagist) | `composer.lock` |
| PyPI | `requirements.txt` |
| NuGet | `packages.lock.json`, `packages.config`, `*.csproj` |
| Go | Terraform and OpenTofu providers and binaries |

Use `--project DIR` (repeatable) for directories outside the web root.

## What each finding contains

- **risk**: the CVSS v3.x base score computed from the vector, mapped to a severity (9.0 and above critical, 7.0 high, 4.0 medium, else low). Without a v3 vector, the severity given by the advisory database is used; malicious packages (`MAL-`) are critical.
- **certainty**: `high` when the exact version was read, `medium` when it was deduced from a constraint such as `requests>=2.20` or a `.csproj` reference.
- **fix**: the smallest fixed version above the installed one, for example "Upgrade lodash to 4.17.21 or later".

The finding identifier is `vulnerable-component`.

## Terraform and OpenTofu

The tool lists versions, it does not analyse the configuration. Providers come from `.terraform.lock.hcl` (exact) and `required_providers` blocks (smallest allowed version, certainty medium); Terraform from `required_version`, `.terraform-version` or `terraform version`; OpenTofu from `.opentofu-version` or `tofu version`.

## What is not covered

OSV does not track WordPress core, plugins and themes, Joomla extensions, Drupal 7 modules or PHP itself. They are listed with "CVEs not checked", never "no CVE". Their versions are still checked for [end of life](end-of-life-software.md). `vendor/composer/installed.json` is not read: `composer.lock` is.

Online or offline? See [network and offline use](offline-and-network.md).

---

## Check your site from the outside too

attackscout-agent sees the inside of your server. To see what the Internet sees of your domain, run the external audit at [attackscout.com/en](https://attackscout.com/en?utm_source=cli&utm_medium=docs&utm_campaign=attackscout-agent).

[Documentation index](index.md) | [End of life](end-of-life-software.md) | [Network](offline-and-network.md) | [CI](ci-integration.md) | [Command line](command-line-reference.md)
