# attackscout-agent : vérifier la sécurité d'un site web depuis le serveur (audit de sécurité auto-hébergé en ligne de commande)

[English](README.md) | [Documentation (en anglais)](docs/index.md)

**attackscout-agent est un outil libre et gratuit d'audit de sécurité en ligne de commande, auto-hébergé.** Lancez-le sur un serveur Linux, macOS ou Windows pour vérifier un site depuis l'intérieur : logiciels en fin de vie, CVE connues dans les fichiers de verrouillage, fichiers exposés dans la racine web, droits des fichiers, en-têtes de sécurité nginx / Apache / IIS, `wp-config.php` et fichiers de certificats TLS.

- **Lecture seule.** Il ne modifie, ne supprime et ne corrige aucun fichier.
- **Rien n'est envoyé par défaut.** Ni télémétrie, ni vérification de mise à jour. Deux options explicites utilisent le réseau (`db update`, `--online`), décrites dans [Réseau : ce qui sort de la machine](#réseau--ce-qui-sort-de-la-machine).
- **Un seul binaire statique**, écrit en Go. Pas d'agent, pas de compte, pas de service à installer.

Il complète [AttackScout](https://attackscout.com/fr?utm_source=cli&utm_medium=cli&utm_campaign=attackscout-cli), qui audite ce qu'Internet voit d'un domaine. Cet outil est à part et gratuit ; il ne fait pas partie du service AttackScout.

## Sommaire

- [Installation](#installation-sous-linux-macos-et-windows)
- [Démarrage rapide et exemple de sortie](#démarrage-rapide-et-exemple-de-sortie)
- [Ce qu'il contrôle](#ce-quil-contrôle)
- [Options et codes de sortie](#options-et-codes-de-sortie)
- [Utilisation en CI](#utilisation-en-ci)
- [Réseau : ce qui sort de la machine](#réseau--ce-qui-sort-de-la-machine)
- [FAQ](#faq)
- [Vérifiez aussi votre site depuis l'extérieur](#vérifiez-aussi-votre-site-depuis-lextérieur)
- [Limites](#limites)

## Installation sous Linux, macOS et Windows

Avec Go 1.26 ou plus récent :

```sh
go install github.com/attackscout/attackscout-agent@latest
```

Des binaires pour Linux, macOS et Windows (amd64 et arm64) sont joints à chaque [version GitHub](https://github.com/AttackScout/attackscout-agent/releases), avec un fichier `checksums.txt`. Les archives s'appellent `attackscout-agent_<version>_<os>_<arch>.tar.gz` (`.zip` sous Windows).

Linux et macOS (remplacez la version et l'architecture) :

```sh
curl -LO https://github.com/AttackScout/attackscout-agent/releases/download/vX.Y.Z/attackscout-agent_X.Y.Z_linux_amd64.tar.gz
curl -LO https://github.com/AttackScout/attackscout-agent/releases/download/vX.Y.Z/checksums.txt
sha256sum --check --ignore-missing checksums.txt
tar -xzf attackscout-agent_X.Y.Z_linux_amd64.tar.gz
sudo install attackscout-agent /usr/local/bin/
```

Windows (PowerShell) : téléchargez le `.zip` depuis la page de la version, comparez-le à `checksums.txt` avec `Get-FileHash -Algorithm SHA256`, extrayez-le, puis lancez `.\attackscout-agent.exe scan`.

Homebrew : bientôt. Vérifiez l'installation avec `attackscout-agent version`.

## Démarrage rapide et exemple de sortie

```sh
# analyse avec détection automatique de la racine web et de nginx / Apache
attackscout-agent scan

# chemins explicites, rapport en français, échec du job sur les constats élevés
attackscout-agent scan --root /var/www/site --nginx /etc/nginx --cert /etc/ssl/site.pem --lang fr --fail-on high

# JSON pour les scripts
attackscout-agent scan --root /var/www/site --json > rapport.json

# télécharger une fois les bases de vulnérabilités OSV (réseau), puis analyser hors ligne
attackscout-agent db update
attackscout-agent scan --root /var/www/site --project /srv/app
```

La sortie ci-dessous est réelle : elle vient de l'outil lancé sur le faux site WordPress et la configuration nginx du dossier `testdata/` de ce dépôt, sur une machine Windows (d'où la ligne « non applicable » pour les droits ; sous Linux ils sont contrôlés). Elle est abrégée : la liste des constats est coupée là où c'est indiqué.

```text
AttackScout CLI 0.1.0 - analyse locale, en lecture seule
Réseau : rien n'a été envoyé
root: wordpress
nginx: nginx

Contrôles
  [échec         ] Fin de vie - Table de fin de vie embarquée dans le binaire, datée du 2026-11-25
  [non vérifié   ] CVE (OSV) - CVE non vérifiées pour 5 composants que OSV ne suit pas (WordPress, extensions Joomla, ...)
  [échec         ] Fichiers sensibles
  [non applicable] Droits des fichiers - Non applicable sous Windows : les droits Unix n'y existent pas et les ACL ne sont pas lues
  [échec         ] wp-config.php
  [échec         ] Configuration du serveur web
  [échec         ] Certificats

Constats
  [CRITIQUE] sensitive-env: Fichier d'environnement sensible dans la racine web : .env (contenu non lu)
      wordpress/.env
      correctif : Sortez le fichier .env de la racine web, puis changez tous les secrets qu'il contient
  [CRITIQUE] wpconfig-salt-default: Clés ou sels de wp-config.php vides ou laissés par défaut : AUTH_KEY, SECURE_AUTH_KEY (valeurs non affichées)
      wordpress/wp-config.php
      correctif : Générez de nouvelles clés et de nouveaux sels (wp config shuffle-salts)
  [ÉLEVÉ] php-eol: PHP 7.4 est en fin de vie (branche 7.4, depuis le 2022-11-28)
      configuration hint
      certitude : moyenne
      correctif : Passez PHP sur une branche maintenue : https://www.php.net/supported-versions.php
  [MOYEN] header-hsts-missing: La configuration nginx ne définit pas Strict-Transport-Security
      nginx
      correctif : Envoyez Strict-Transport-Security: max-age=31536000; includeSubDomains en HTTPS (add_header Strict-Transport-Security "..." always;)
  [...]

Bilan : 4 critique, 4 élevé, 5 moyen, 10 faible, 0 info

Cette analyse voit l'intérieur du serveur. Pour voir ce qu'Internet en voit, lancez l'audit externe gratuit :
https://attackscout.com/?utm_source=cli&utm_medium=cli&utm_campaign=attackscout-cli
```

Avec `--fail-on high`, la même exécution se termine avec le code `1`.

## Ce qu'il contrôle

Chaque constat a un identifiant stable, une sévérité (`info`, `low`, `medium`, `high`, `critical`), un message court et un correctif. Chaque contrôle donne un statut : `pass`, `fail`, `not_applicable` ou `not_checked`. Un contrôle qui n'a pas de sens sur un système est `not_applicable` ; un contrôle qui n'a pas pu s'exécuter est `not_checked`. Aucun des deux n'est affiché comme `pass`.

| Contrôle | Ce qui est regardé | Guide (en anglais) |
|---|---|---|
| Fin de vie | PHP, Node.js, .NET, WordPress (cœur, extensions, thèmes), Drupal, Joomla, PrestaShop, React, Next.js, d'après une table de fin de vie embarquée dans le binaire | [End-of-life software](docs/end-of-life-software.md) |
| Vulnérabilités connues | Fichiers de verrouillage npm, Composer, PyPI, NuGet et Go, fournisseurs Terraform et OpenTofu, comparés à [OSV](https://osv.dev) | [Known vulnerabilities (CVE)](docs/known-vulnerabilities-cve.md) |
| Fichiers sensibles | `.env`, `.git/`, dumps SQL et archives, `phpinfo.php`, journaux, clés privées, `.htpasswd`, `terraform.tfstate`... Les noms seulement : le contenu n'est jamais lu | [Exposed files in the web root](docs/exposed-files-web-root.md) |
| Droits des fichiers | Fichiers et répertoires modifiables par tous, `777`, secrets lisibles par tous (Unix seulement) | [File permissions](docs/file-permissions.md) |
| Configuration du serveur web | nginx, Apache et IIS : HSTS, CSP, X-Content-Type-Options, protection contre l'inclusion en cadre, Referrer-Policy, version affichée, liste des répertoires | [Security headers](docs/web-server-security-headers.md) |
| wp-config.php | Clés et sels par défaut ou absents, `WP_DEBUG`, `WP_DEBUG_DISPLAY`, `DISALLOW_FILE_EDIT`. Les valeurs secrètes ne sont jamais affichées | [wp-config.php security](docs/wordpress-wp-config-security.md) |
| Certificats | Fichiers PEM locaux : expiration, expiration dans moins de 30 jours, chaîne expirée, clé faible, signature SHA-1 ou MD5 | [Certificate check](docs/ssl-certificate-check.md) |

Il lit les **fichiers** de certificats sur le disque. Il n'ouvre aucune connexion vers votre site : il ne teste donc pas les versions du protocole TLS ni les suites de chiffrement qu'un visiteur négocie.

## Options et codes de sortie

| Option | Rôle |
|---|---|
| `--root DIR` | Racine web. Par défaut : celle de la configuration nginx / Apache, puis `/var/www/html`, `/srv/www`, `/usr/share/nginx/html`, `/var/www` (`C:\inetpub\wwwroot` sous Windows), puis le répertoire courant s'il ressemble à un site |
| `--project DIR` | Répertoire supplémentaire avec des fichiers de verrouillage ou Terraform (répétable) |
| `--nginx DIR` | Configuration nginx. Par défaut : `/etc/nginx`, `/usr/local/etc/nginx`, `/opt/homebrew/etc/nginx` (`C:\nginx\conf`) |
| `--apache DIR` | Configuration Apache. Par défaut : `/etc/apache2`, `/etc/httpd`, `/usr/local/etc/httpd`, `/opt/homebrew/etc/httpd` (`C:\Apache24\conf`) |
| `--cert FILE` | Certificat PEM à vérifier (répétable). Les certificats cités dans la configuration nginx / Apache sont ajoutés |
| `--json` | Sortie JSON au lieu du texte |
| `--fail-on SEV` | Code de sortie 1 si un constat atteint `info`, `low`, `medium`, `high` ou `critical`. Par défaut `none` |
| `--lang en\|fr` | Langue du rapport. Par défaut `en` |
| `--online` | Cherche les CVE avec api.osv.dev au lieu de la base locale |
| `--db DIR` | Répertoire des bases OSV. Par défaut : cache utilisateur + `attackscout-agent` |

Commandes : `scan`, `db update` (`--db`, `--ecosystems npm,Packagist,PyPI,NuGet,Go`), `version`, `help`.

Codes de sortie : `0` succès, `1` un constat atteint `--fail-on` (ou `db update` a échoué pour un écosystème), `2` erreur d'usage. Référence complète (en anglais) : [command line](docs/command-line-reference.md).

## Utilisation en CI

Analysez un projet récupéré par le job (fichiers de verrouillage, Terraform, racine web) et faites échouer le job sur les constats élevés :

```yaml
# .github/workflows/server-check.yml
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
      - run: attackscout-agent db update            # réseau : télécharge les archives OSV
      - run: attackscout-agent scan --root . --project . --fail-on high --lang fr
```

L'étape échoue avec le code `1` quand un constat est `high` ou `critical`. Sur un serveur, la même commande fonctionne depuis cron ou un script de déploiement. Plus d'exemples : [use in CI](docs/ci-integration.md).

## Réseau : ce qui sort de la machine

**Par défaut, rien.** Aucun appel HTTP, aucune télémétrie, aucune vérification de mise à jour. L'analyse lit des fichiers locaux, lance quelques commandes locales si elles existent (`php -v`, `node --version`, `dotnet --list-runtimes`, `terraform version`, `tofu version`), et n'écrit rien.

Deux commandes explicites utilisent le réseau, et elles seules :

- `attackscout-agent db update` télécharge les archives OSV (`all.zip`) de npm, Packagist, PyPI, NuGet et Go depuis `https://osv-vulnerabilities.storage.googleapis.com`, dans le répertoire de cache de l'utilisateur (`--db` pour le changer). Rien sur votre serveur n'est envoyé.
- `attackscout-agent scan --online` envoie à `https://api.osv.dev` le **nom, la version et l'écosystème** de chaque paquet, puis récupère le détail des vulnérabilités correspondantes par leur identifiant. Aucun chemin, nom de fichier, nom de machine ni nom de domaine n'est envoyé. Les paquets npm locaux (liens `file:`) ne sont pas envoyés.

Sans base locale et sans `--online`, le rapport indique « CVE non vérifiées » au lieu d'affirmer qu'il n'y en a pas.

Comment c'est garanti : `nonetwork_test.go` analyse chaque fichier source et seul `internal/vulns` peut importer un paquet réseau ; `TestDefaultScanUsesNoNetwork` lance une analyse par défaut complète avec une garde sur `http.DefaultTransport` et échoue à la moindre requête. Détails (en anglais) : [network and offline use](docs/offline-and-network.md).

## FAQ

### Comment vérifier la sécurité de mon site web depuis le serveur ?

Installez `attackscout-agent` sur le serveur et lancez `attackscout-agent scan`. Il détecte la racine web et la configuration nginx ou Apache, puis signale les logiciels en fin de vie, les fichiers exposés, les droits risqués, les en-têtes de sécurité absents et les problèmes de certificat, chacun avec un correctif.

### Existe-t-il un outil libre, gratuit et auto-hébergé d'audit de sécurité pour un serveur web ?

Celui-ci est sous licence MIT, gratuit, et s'exécute en local sans compte. Il ne contrôle que le côté serveur ; pour voir ce que voient les visiteurs et les scanners, utilisez aussi une analyse externe (voir plus bas).

### Envoie-t-il mes données quelque part ?

Pas par défaut. L'analyse par défaut ne fait aucune requête réseau, et un test échoue si elle en fait. `db update` télécharge des données publiques de vulnérabilités et n'envoie rien sur votre serveur. `--online` envoie à api.osv.dev des noms de paquets, des versions et des écosystèmes, rien d'autre.

### Comment repérer des fichiers .env, .git ou de sauvegarde exposés dans la racine web ?

`scan` parcourt la racine web (dix niveaux de profondeur, `node_modules` et `vendor` ignorés) et signale par leur nom les `.env`, `.git/`, dumps SQL, archives, `phpinfo.php`, journaux et clés privées. Il n'ouvre jamais leur contenu. Voir [exposed files](docs/exposed-files-web-root.md) (en anglais).

### Comment vérifier les en-têtes de sécurité (HSTS, CSP) dans nginx ou Apache ?

`scan` lit vos fichiers de configuration nginx, Apache et IIS et signale les en-têtes non définis. Il lit la configuration, il n'interroge pas votre site : un en-tête ajouté par un proxy ou un CDN placé devant le serveur n'est donc pas vu. Voir [security headers](docs/web-server-security-headers.md) (en anglais).

### Peut-il vérifier le certificat TLS de mon serveur ?

Il vérifie des fichiers de certificats PEM : ceux que vous passez avec `--cert` et ceux cités par `ssl_certificate` ou `SSLCertificateFile`. Il signale l'expiration, un certificat qui expire dans moins de 30 jours, une chaîne expirée, les clés faibles et les signatures SHA-1 ou MD5. Il ne se connecte pas au site. Voir [certificate check](docs/ssl-certificate-check.md) (en anglais).

### Puis-je l'utiliser dans une chaîne de CI ?

Oui. Utilisez `--fail-on high` (ou une autre sévérité) : le job échoue avec le code `1`. Utilisez `--json` pour garder le rapport comme artefact. Voir [use in CI](docs/ci-integration.md) (en anglais).

### Fonctionne-t-il sous Windows ?

Oui. Il s'exécute sous Windows et contrôle le `web.config` d'IIS, nginx et Apache. Les droits des fichiers y sont `not_applicable`, car les droits Unix n'existent pas sous Windows et les ACL ne sont pas lues.

## Vérifiez aussi votre site depuis l'extérieur

Cet outil voit l'intérieur de votre serveur. Il ne voit pas ce que voit un visiteur ou un scanner : les en-têtes réellement envoyés par votre proxy ou votre CDN, ce qui est joignable depuis Internet, ou le certificat réellement servi. Pour cela, lancez l'audit externe de votre domaine sur [attackscout.com/fr](https://attackscout.com/fr?utm_source=cli&utm_medium=cli&utm_campaign=attackscout-cli).

## Limites

- La comparaison des versions est faite par osv-scalibr : SemVer pour npm, règles Composer pour Packagist, PEP 440 pour PyPI, règles NuGet et Go. Les noms de branches Composer (`dev-main`) ne sont pas comparables.
- Une contrainte (`requests>=2.20`, référence `.csproj`, Terraform `~> 5.0`) est remplacée par sa plus petite version : certitude `medium`.
- `vendor/composer/installed.json` n'est pas lu : `composer.lock` l'est.
- OSV ne couvre ni WordPress, ni les extensions Joomla, ni PHP lui-même : ces versions ne sont contrôlées que pour la fin de vie, et signalées « CVE non vérifiées ».
- Terraform et OpenTofu : les versions sont listées, la configuration n'est pas analysée. [tfsec](https://github.com/aquasecurity/tfsec) et [Checkov](https://github.com/bridgecrewio/checkov) le font.
- La table de fin de vie est aussi récente que la version que vous utilisez.
- Les droits ne sont pas contrôlés sous Windows.

## Développement

```sh
go test ./...
go vet ./...
```

Les jeux d'essai sont dans `testdata/` (faux sites WordPress, Drupal, Joomla et PrestaShop, configurations nginx, Apache et IIS, fichiers de verrouillage, fichiers Terraform). Les tests n'utilisent jamais le réseau : `db update` et `--online` sont testés contre des serveurs `httptest` locaux.

## Licence

MIT, voir [LICENSE](LICENSE). Les composants tiers sont listés dans [NOTICE](NOTICE) : osv-scalibr et les liaisons OSV sont sous licence Apache 2.0, compatible avec la licence MIT de cet outil.
