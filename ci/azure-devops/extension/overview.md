# AttackScout agent for Azure Pipelines

Checks a website from the inside of its server or repository: known CVEs (OSV) flagged with the CISA KEV list, end of life (endoflife.date), exposed `.git`, `.env` and backups, phpinfo pages, file permissions, wp-config.php and web server configuration (nginx, Apache, IIS).

```yaml
steps:
  - task: AttackScoutAgent@0
    inputs:
      path: $(Build.SourcesDirectory)
      failOn: high
```

The task writes `attackscout-agent.sarif` in the `CodeAnalysisLogs` artifact, shown by the SARIF SAST Scans Tab extension. The scan itself is offline; only the database update step downloads OSV, CISA KEV and endoflife.date data.

Documentation: https://github.com/AttackScout/attackscout-agent/blob/main/docs/azure-devops.md
