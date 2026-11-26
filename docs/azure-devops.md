# Azure DevOps: CVE and website security scan in Azure Pipelines

Two ways to run `attackscout-agent` in Azure Pipelines: a YAML steps template that works today, and a Marketplace task (`AttackScoutAgent@0`) whose source is in `ci/azure-devops/extension`. Both write a SARIF report in the `CodeAnalysisLogs` build artifact, which the free **SARIF SAST Scans Tab** extension (Microsoft DevLabs) shows in a Scans tab of the build.

## YAML template

Copy `ci/azure-devops/attackscout-agent.yml` into your repository, then:

```yaml
# azure-pipelines.yml
trigger: [main]
schedules:
  - cron: "17 5 * * 1"
    displayName: weekly CVE check
    branches: { include: [main] }
    always: true

pool:
  vmImage: ubuntu-latest

steps:
  - checkout: self
  - template: ci/attackscout-agent.yml
    parameters:
      failOn: high
```

Parameters: `version` (`0.2.0`), `path` (`$(Build.SourcesDirectory)`), `failOn` (`critical`, `high`, `medium`, `low`, `info`, `none`), `args`, `dbUpdate` (`true`), `ecosystems`. The template downloads the release archive, checks it against `checksums.txt`, runs `db update`, writes the SARIF report, then runs the scan with the threshold. Linux, macOS and Windows agents are supported (Windows through the Git Bash of the hosted agents).

## Marketplace task

```yaml
steps:
  - task: AttackScoutAgent@0
    inputs:
      path: $(Build.SourcesDirectory)
      failOn: high
```

Inputs: `version`, `path`, `failOn`, `dbUpdate`, `ecosystems`, `args`, `sarifDir`. The task has no dependency: a Node 20 script downloads the release, checks its SHA-256, and uploads the SARIF file as `CodeAnalysisLogs`.

To package it yourself (until it is listed on the Marketplace):

```sh
cd ci/azure-devops/extension
# add images/icon.png (128x128), then:
npx tfx-cli extension create --manifest-globs vss-extension.json
```

Share the `.vsix` privately with your organization from the Marketplace publisher page.

## What fails the pipeline

The scan exits with code `1` when a finding reaches `failOn`; the template and the task fail the step. CVEs listed by CISA as exploited in the wild are always critical. See [how deep the CVE scan goes](cve-scanning-depth.md) and the [command line reference](command-line-reference.md).

---

## Check your site from the outside too

To see what the Internet sees of your domain, run the free external audit at [attackscout.com/en](https://attackscout.com/en?utm_source=attackscout-agent&utm_medium=docs&utm_campaign=azure-devops).

[Documentation index](index.md) | [GitHub Actions](github-actions.md) | [GitLab CI](gitlab-ci.md) | [Use in CI](ci-integration.md)
