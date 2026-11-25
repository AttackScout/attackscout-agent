# Find world-writable files and chmod 777 directories on a Linux web server

Files that every local user can write to, or secrets that every local user can read, turn a small compromise into a large one. `attackscout-agent scan` checks Unix permission bits under the web root.

```sh
attackscout-agent scan --root /var/www/site
```

## What is reported

| ID | Severity | Meaning |
|---|---|---|
| `perm-dir-777` | high | Directory with mode 0777 |
| `perm-dir-world-writable` | high | Directory writable by others, without the sticky bit |
| `perm-file-world-writable` | high | File writable by others |
| `perm-secret-world-readable` | medium | `wp-config.php`, `.env`, `settings.php`, `configuration.php`, `parameters.php` or `auth.json` readable by others |

Symbolic links are skipped. At most 20 findings are listed per rule; the rest is counted in one summary line.

## Fix

Use `chmod` and `chown` so that the web server user can read what it serves and write only where it must (uploads, cache). A common baseline is 755 for directories, 644 for files, and 640 or 600 for files holding secrets.

## Windows

On Windows the check is reported `not_applicable`: Unix permission bits do not exist there, and ACLs are not read.

---

## Check your site from the outside too

attackscout-agent sees the inside of your server. To see what the Internet sees of your domain, run the external audit at [attackscout.com/en](https://attackscout.com/en?utm_source=cli&utm_medium=docs&utm_campaign=attackscout-agent).

[Documentation index](index.md) | [Exposed files](exposed-files-web-root.md) | [wp-config.php](wordpress-wp-config-security.md) | [Command line](command-line-reference.md)
