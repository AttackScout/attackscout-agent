# Find exposed .env, .git, SQL dumps, backups and phpinfo files in a web root

A forgotten `.env`, a `backup.sql` or a `.git` directory in the web root can hand secrets to anyone who guesses the URL. `attackscout-agent scan` lists them from the server's file system.

```sh
attackscout-agent scan --root /var/www/site
```

**Only names are read.** Contents are never opened or printed. The walk goes ten levels deep, stops at 200,000 entries, and does not descend into `node_modules` or `vendor`.

## What is reported

| ID | Severity | Matches |
|---|---|---|
| `sensitive-env` | critical | `.env`, `.env.*` |
| `sensitive-env-sample` | low | `.env.example`, `.env.sample`, `.env.dist` |
| `sensitive-vcs` | high | `.git/`, `.svn/`, `.hg/`, `.bzr/` |
| `sensitive-backup` | high; critical for database dumps and copies of `wp-config` or `.env` | `.sql`, `.sql.gz`, `.dump`, `.zip`, `.tar`, `.tar.gz`, `.tgz`, `.7z`, `.rar`, `.bak`, `.old`, `.orig`, `.save`, `.swp`, names ending in `~` |
| `sensitive-phpinfo` | medium | `phpinfo.php`, `info.php`, `php_info.php` |
| `phpinfo-exposed` | medium | any other PHP file of 64 KB or less, three levels deep at most, that calls `phpinfo()` outside a comment (CMS cores and `vendor/` skipped). This is the only check that opens a file of the web root, to look for that call |
| `sensitive-ds-store` | low | `.DS_Store` |
| `sensitive-composer` | low | `composer.json`, `composer.lock` at the root |
| `sensitive-auth-json` | critical | `auth.json` |
| `sensitive-log` | medium | `*.log`, `error_log` |
| `sensitive-htpasswd` | medium | `.htpasswd` |
| `sensitive-private-key` | critical | `.key`, `.pem`, `.p12`, `.pfx`, `id_rsa`, `id_ed25519` |
| `sensitive-tfstate` | critical | `*.tfstate`, `*.tfstate.backup` |

## Fix

Move the file outside the web root and, for anything that held secrets, rotate them: a file that sat in the web root may already have been downloaded. Each finding gives the specific advice.

## A file listed here is not necessarily reachable

The scan looks at the file system, not at your site. A file may be blocked by a server rule, or reachable through a path you did not think of. To confirm what a visitor can actually fetch, check from the outside.

---

## Check your site from the outside too

attackscout-agent sees the inside of your server. To see what the Internet sees of your domain, run the free external audit at [attackscout.com/en](https://attackscout.com/en?utm_source=attackscout-agent&utm_medium=docs&utm_campaign=docs).

[Documentation index](index.md) | [File permissions](file-permissions.md) | [wp-config.php](wordpress-wp-config-security.md) | [Headers](web-server-security-headers.md) | [Command line](command-line-reference.md)
