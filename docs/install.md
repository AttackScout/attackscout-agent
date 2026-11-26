# Install attackscout-agent: Homebrew, Scoop, winget, Docker or a binary

attackscout-agent is one static binary for Linux, macOS and Windows (amd64 and arm64). Pick the channel of your system.

| Channel | Command |
|---|---|
| Homebrew (macOS, Linux) | `brew install --cask attackscout/tap/attackscout-agent` |
| Scoop (Windows) | `scoop bucket add attackscout https://github.com/AttackScout/scoop-bucket` then `scoop install attackscout-agent` |
| winget (Windows) | `winget install AttackScout.AttackscoutAgent` |
| Docker | `docker run --rm -v "$PWD:/src:ro" ghcr.io/attackscout/attackscout-agent:0.2.0` |
| Go | `go install github.com/attackscout/attackscout-agent@latest` |
| Binary | archives and `checksums.txt` on the [GitHub releases](https://github.com/AttackScout/attackscout-agent/releases) |

Check the install with `attackscout-agent version`.

## Docker

The image runs as an unprivileged user and scans `/src` by default. Mount the directory read-only, and a volume for the databases:

```sh
docker run --rm -v attackscout-db:/home/scanner/.cache -v "$PWD:/src:ro" \
  ghcr.io/attackscout/attackscout-agent:0.2.0 db update --db /home/scanner/.cache/attackscout-agent
docker run --rm -v attackscout-db:/home/scanner/.cache -v "$PWD:/src:ro" \
  ghcr.io/attackscout/attackscout-agent:0.2.0 scan --root /src --project /src --db /home/scanner/.cache/attackscout-agent
```

To read the system packages of the host, mount its root read-only and pass `--sysroot /host`.

## Verify a binary

```sh
sha256sum --check --ignore-missing checksums.txt          # Linux
shasum -a 256 --check --ignore-missing checksums.txt      # macOS
```

On Windows: `Get-FileHash -Algorithm SHA256 attackscout-agent_0.2.0_windows_amd64.zip` and compare with `checksums.txt`.

## For maintainers

Releases are built by goreleaser (`.goreleaser.yaml`): archives, checksums, the Homebrew cask in `AttackScout/homebrew-tap`, the Scoop manifest in `AttackScout/scoop-bucket` and the multi-architecture image on `ghcr.io/attackscout/attackscout-agent`. The winget manifests are prepared in `packaging/winget`: after the release, fill their SHA-256 values with `pwsh packaging/winget/fill-checksums.ps1 -Version 0.2.0 -Checksums dist/checksums.txt`, then submit them to `microsoft/winget-pkgs`.

---

## Check your site from the outside too

To see what the Internet sees of your domain, run the free external audit at [attackscout.com/en](https://attackscout.com/en?utm_source=attackscout-agent&utm_medium=docs&utm_campaign=install).

[Documentation index](index.md) | [Command line](command-line-reference.md) | [GitHub Actions](github-actions.md)
