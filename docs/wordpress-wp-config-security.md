# Audit wp-config.php: default salts, WP_DEBUG and dashboard file editing

`attackscout-agent scan` reads `wp-config.php` and reports risky settings. It also looks for the file one level above the web root, as WordPress allows. If no `wp-config.php` exists, the check is `not_applicable`.

```sh
attackscout-agent scan --root /var/www/wordpress
```

**Secret values are never printed.** The report names the constants (`AUTH_KEY`), not their values.

## What is reported

| ID | Severity | Meaning |
|---|---|---|
| `wpconfig-salt-default` | critical | One of the eight keys or salts is empty or left at "put your unique phrase here" |
| `wpconfig-salt-missing` | high | One of the eight keys or salts is not defined (`AUTH_KEY`, `SECURE_AUTH_KEY`, `LOGGED_IN_KEY`, `NONCE_KEY`, `AUTH_SALT`, `SECURE_AUTH_SALT`, `LOGGED_IN_SALT`, `NONCE_SALT`) |
| `wpconfig-debug` | medium | `WP_DEBUG` is true |
| `wpconfig-debug-display` | high | `WP_DEBUG_DISPLAY` is true, or `WP_DEBUG` is true without `WP_DEBUG_DISPLAY`: PHP errors are shown to visitors |
| `wpconfig-file-edit` | low | `DISALLOW_FILE_EDIT` is not true: an admin account can edit PHP code from the dashboard |

## Fix

Generate new keys and salts (`wp config shuffle-salts` with WP-CLI) and add:

```php
define( 'WP_DEBUG', false );
define( 'DISALLOW_FILE_EDIT', true );
```

Changing the salts logs every user out, which is expected.

## Related checks

A copy of the file left in the web root (`wp-config.php.bak`) is reported as a critical [exposed file](exposed-files-web-root.md); the file's [permissions](file-permissions.md) are checked too. WordPress core, plugins and themes are checked for [end of life](end-of-life-software.md), but not for CVEs, because OSV does not track them.

---

## Check your site from the outside too

attackscout-agent sees the inside of your server. To see what the Internet sees of your domain, run the free external audit at [attackscout.com/en](https://attackscout.com/en?utm_source=attackscout-agent&utm_medium=docs&utm_campaign=docs).

[Documentation index](index.md) | [Exposed files](exposed-files-web-root.md) | [File permissions](file-permissions.md) | [End of life](end-of-life-software.md)
