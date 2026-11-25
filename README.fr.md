# attackscout-cli

[English](README.md)

Outil libre et gratuit en ligne de commande qui vérifie un site **depuis l'intérieur de son serveur** : logiciels obsolètes ou en fin de vie, CVE connues, fichiers exposés, droits des fichiers, en-têtes du serveur web, `wp-config.php` et certificats.

Il ne fait que lire. Il ne modifie, ne supprime et ne corrige aucun fichier, et il n'envoie **rien** sur le réseau, sauf si vous le demandez (`db update`, `--online`).

Il complète [AttackScout](https://attackscout.com/?utm_source=cli&utm_medium=cli&utm_campaign=attackscout-cli), qui audite ce qu'Internet voit d'un domaine. Cet outil est à part et gratuit ; il ne fait pas partie du service AttackScout.

## Installation

```sh
go install github.com/attackscout/attackscout-cli@latest
```

Des binaires pour Linux, macOS et Windows (amd64 et arm64) sont joints à chaque [version GitHub](https://github.com/attackscout/attackscout-cli/releases), avec un fichier `checksums.txt`. Homebrew : bientôt.

La compilation depuis les sources demande Go 1.26 ou plus récent.

## Utilisation

```sh
# analyse avec détection automatique de la racine web et de nginx / Apache
attackscout-cli scan

# chemins explicites, rapport en français, échec du job de CI sur les constats élevés
attackscout-cli scan --root /var/www/site --nginx /etc/nginx --cert /etc/ssl/site.pem --lang fr --fail-on high

# JSON pour les scripts
attackscout-cli scan --root /var/www/site --json > rapport.json

# télécharger une fois les bases de vulnérabilités OSV (réseau), puis analyser hors ligne
attackscout-cli db update
attackscout-cli scan --root /var/www/site --project /srv/app --project /srv/infra
```

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
| `--online` | Cherche les CVE avec api.osv.dev au lieu de la base locale (voir plus bas) |
| `--db DIR` | Répertoire des bases OSV. Par défaut : cache utilisateur + `attackscout-cli` |

Codes de sortie : `0` succès, `1` un constat atteint `--fail-on` (ou `db update` a échoué pour un écosystème), `2` erreur d'utilisation.

Chaque rapport se termine par un lien vers l'audit externe gratuit : <https://attackscout.com/?utm_source=cli&utm_medium=cli&utm_campaign=attackscout-cli>.

## Statuts des contrôles

Chaque contrôle donne un statut : `pass`, `fail`, `not_applicable` ou `not_checked`. Un contrôle qui n'a pas de sens sur un système affiche `not_applicable` (« non applicable »), jamais `pass`. Un contrôle qui n'a pas pu tourner (pas de racine web, pas de configuration, pas de base de vulnérabilités) affiche `not_checked` (« non vérifié »), jamais `pass`.

## Contrôles

Chaque constat a un identifiant stable, une gravité (`info`, `low`, `medium`, `high`, `critical`), un message court et un correctif.

### 1. Versions et fin de vie (`end-of-life`)

| Quoi | Origine de la version |
|---|---|
| PHP | `php -v`, sinon indices de configuration (sockets `php8.1-fpm`, `/etc/php/X.Y`) |
| Node.js | `node --version`, sinon `.nvmrc` / `.node-version` |
| .NET | `dotnet --list-runtimes`, sinon `<TargetFramework>` des fichiers `.csproj` |
| WordPress | `wp-includes/version.php`, extensions (en-têtes des plugins), thèmes (`style.css`) |
| Drupal | `core/lib/Drupal.php` ou `includes/bootstrap.inc`, modules et thèmes contrib (`*.info.yml`) |
| Joomla | `administrator/manifests/files/joomla.xml`, composants, modules, plugins, templates (manifestes XML) |
| PrestaShop | `app/AppKernel.php` ou `config/settings.inc.php` |
| React, Next.js | fichiers de verrouillage, sinon `node_modules/react/package.json` et `node_modules/next/package.json` |

Identifiants : `<produit>-eol` (élevé), `<produit>-eol-soon` (moyen, moins de 90 jours), `<produit>-patch-behind` (faible), `<produit>-version` (info).

La table de fin de vie est **embarquée dans le binaire** (`go:embed`) avec sa date (`internal/eol/data.json`, affichée dans chaque rapport). Elle s'appuie sur endoflife.date (MIT) et sur les pages des éditeurs ; la date de l'éditeur l'emporte quand elle est plus tôt. Chaque nouvelle version de l'outil apporte une table à jour.

### 2. Vulnérabilités connues (`vulnerabilities`)

L'inventaire est comparé à la base [OSV](https://osv.dev) avec la bibliothèque [osv-scalibr](https://github.com/google/osv-scalibr) de Google (Apache-2.0, version épinglée dans `go.mod`). Les fichiers de verrouillage sont lus par les extracteurs d'osv-scalibr :

| Écosystème | Fichiers |
|---|---|
| npm | `package-lock.json`, `yarn.lock` (v1 et Berry), `pnpm-lock.yaml` |
| Composer (Packagist) | `composer.lock` |
| PyPI | `requirements.txt` |
| NuGet | `packages.lock.json`, `packages.config`, `*.csproj` |
| Go | fournisseurs et binaires Terraform et OpenTofu (voir plus bas) |

Pour chaque CVE :

- **risque** : score de base CVSS v3.x calculé depuis le vecteur, traduit en gravité (9,0 et plus critique, 7,0 et plus élevé, 4,0 et plus moyen, sinon faible). Sans vecteur v3, la gravité donnée par la base d'avis est reprise ; un paquet malveillant (`MAL-`) est critique ;
- **certitude** : `élevée` si la version exacte a été lue (fichier de verrouillage, en-tête de version, sortie de commande), `moyenne` si elle est déduite (contrainte comme `requests>=2.20`, référence `.csproj`, indice de configuration) ;
- **correctif** : la plus petite version corrigée au-dessus de la version installée (événement OSV `fixed`), en clair : « Mettez lodash à jour en version 4.17.21 ou plus récente ».

Les composants que OSV ne suit pas (cœur, extensions et thèmes WordPress, extensions Joomla, modules Drupal 7) sont listés avec « CVE non vérifiées », jamais « aucune CVE ».

Identifiant : `vulnerable-component`.

#### Terraform et OpenTofu (inventaire seulement)

L'outil liste les versions, il n'analyse pas la configuration :

- fournisseurs lus dans `.terraform.lock.hcl` (version exacte, certitude élevée) et dans les blocs `required_providers` des fichiers `.tf` (plus petite version admise par la contrainte, certitude moyenne) ;
- Terraform depuis `required_version`, `.terraform-version` ou `terraform version` ; OpenTofu depuis `.opentofu-version` ou `tofu version`.

Ils sont cherchés dans l'écosystème Go d'OSV : `github.com/<namespace>/terraform-provider-<nom>`, `github.com/hashicorp/terraform`, `github.com/opentofu/opentofu`. Si OSV ne connaît pas un module, le rapport affiche « CVE non vérifiées ».

### 3. Fichiers sensibles dans la racine web (`sensitive-files`)

Seuls les noms sont lus ; le contenu n'est jamais ouvert ni affiché.

`sensitive-env` (`.env`, `.env.*`, critique), `sensitive-env-sample` (faible), `sensitive-vcs` (`.git/`, `.svn/`, `.hg/`, `.bzr/`, élevé), `sensitive-backup` (`.sql`, `.zip`, `.tar.gz`, `.tgz`, `.7z`, `.rar`, `.bak`, `.old`, `.orig`, `.swp`, `~`... ; critique pour les exports de base et les copies de `wp-config` ou `.env`), `sensitive-phpinfo` (`phpinfo.php`, `info.php`), `sensitive-ds-store`, `sensitive-composer` (`composer.json` / `composer.lock` à la racine), `sensitive-auth-json`, `sensitive-log`, `sensitive-htpasswd`, `sensitive-private-key` (`.key`, `.pem`, `.p12`, `id_rsa`...), `sensitive-tfstate`.

### 4. Droits des fichiers (`permissions`)

`perm-file-world-writable`, `perm-dir-777`, `perm-dir-world-writable` (sans sticky bit), `perm-secret-world-readable` (`wp-config.php`, `.env`, `settings.php`, `configuration.php`, `auth.json`...). Sous Windows, le contrôle est `not_applicable` : les droits Unix n'y existent pas et les ACL ne sont pas lues.

### 5. Configuration du serveur web (`web-server`)

nginx (sites activés seulement), Apache (avec le `.htaccess` de la racine web) et IIS (`web.config` de la racine web, lu avec `encoding/xml` ; s'il est illisible, la partie IIS est `not_checked`).

`header-hsts-missing` (moyen), `header-csp-missing`, `header-xcto-missing`, `header-frame-missing` (X-Frame-Options ou CSP `frame-ancestors`), `header-referrer-missing`, `server-tokens` (`server_tokens`, `ServerTokens`, `removeServerHeader` d'IIS), `server-signature` (`ServerSignature`), `x-powered-by` (IIS), `directory-listing` (`autoindex on`, `Options Indexes`, `directoryBrowse`).

### 6. wp-config.php (`wp-config`)

`wpconfig-salt-default` (clés ou sels vides ou « put your unique phrase here », critique), `wpconfig-salt-missing` (élevé), `wpconfig-debug`, `wpconfig-debug-display` (`WP_DEBUG_DISPLAY` à true, ou `WP_DEBUG` à true sans lui), `wpconfig-file-edit` (`DISALLOW_FILE_EDIT` absent). Les valeurs secrètes ne sont jamais affichées. `wp-config.php` est aussi cherché un niveau au-dessus de la racine web, comme WordPress le permet.

### 7. Certificats (`certificates`)

Fichiers PEM passés par `--cert` ou cités par `ssl_certificate` / `SSLCertificateFile` : `cert-expired` (critique), `cert-expiring` (moins de 30 jours, élevé), `cert-chain-expired`, `cert-weak-key` (RSA sous 2048 bits, ECDSA sous 256, DSA), `cert-weak-signature` (MD5, SHA-1), `cert-valid` (info). Les clés privées du même fichier sont ignorées et jamais affichées.

## Réseau : ce qui sort de la machine

**Par défaut, rien.** Aucun appel HTTP, aucune télémétrie, aucune vérification de mise à jour. L'analyse lit des fichiers locaux, lance quelques commandes locales si elles existent (`php -v`, `node --version`, `dotnet --list-runtimes`, `terraform version`, `tofu version`) et n'écrit rien.

Deux commandes explicites utilisent le réseau, et elles seules :

- `attackscout-cli db update` télécharge les archives OSV (`all.zip`) de npm, Packagist, PyPI, NuGet et Go depuis `https://osv-vulnerabilities.storage.googleapis.com`, avec le mécanisme de téléchargement d'osv-scalibr, dans le cache utilisateur (`--db` pour le changer). Rien sur votre serveur n'est envoyé. Choix des écosystèmes avec `--ecosystems npm,Packagist`.
- `attackscout-cli scan --online` envoie à `https://api.osv.dev` (`/v1/querybatch`) le **nom, la version et l'écosystème** de chaque paquet, puis récupère le détail des vulnérabilités trouvées par leur identifiant (`/v1/vulns/<id>`). Aucun chemin, nom de fichier, nom d'hôte ni nom de domaine n'est envoyé. C'est ce qu'envoie l'enrichisseur `osvdev` d'osv-scalibr (`pkgToQuery`), et un test le vérifie. Les paquets npm locaux (liens `file:`) ne sont pas envoyés.

Sans base locale ni `--online`, le rapport affiche « CVE non vérifiées : lancez attackscout-cli db update » au lieu d'affirmer qu'il n'y a aucune CVE.

Comment c'est garanti :

- `nonetwork_test.go` analyse chaque fichier source : seul `internal/vulns` peut importer un paquet réseau, et ses fonctions réseau ne sont appelées que par `onlineMatcher` (`--online`) et `runDBUpdate` (`db update`) ;
- `internal/cli.TestDefaultScanUsesNoNetwork` remplace `http.DefaultTransport` par un garde qui compte chaque requête, lance une analyse complète par défaut avec une base locale et échoue à la moindre requête ;
- sur le chemin par défaut, osv-scalibr reçoit un client HTTP qui refuse toute requête.

## Limites

- La comparaison des versions est faite par osv-scalibr : SemVer pour npm, règles Composer pour Packagist, PEP 440 pour PyPI, règles NuGet et Go. Les noms de branche Composer (`dev-main`) ne sont pas comparables.
- Une contrainte (`requests>=2.20`, référence `.csproj`, Terraform `~> 5.0`) est remplacée par sa plus petite version : certitude moyenne, le résultat peut différer de ce qui est installé.
- `vendor/composer/installed.json` n'est pas lu : `composer.lock` l'est.
- OSV ne couvre ni WordPress, ni les extensions Joomla, ni PHP lui-même : ces versions ne sont vérifiées que pour la fin de vie.
- La table de fin de vie est aussi fraîche que la version de l'outil utilisée.
- Les droits ne sont pas vérifiés sous Windows.

## Pistes, hors de cette version

- Analyse de configuration Terraform : [tfsec](https://github.com/aquasecurity/tfsec) et [Checkov](https://github.com/bridgecrewio/checkov) le font déjà bien. Cet outil ne liste que les versions Terraform.
- Formule Homebrew.

## Développement

```sh
go test ./...
go vet ./...
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0 run ./...
```

Les fixtures sont dans `testdata/` (faux sites WordPress, Drupal, Joomla et PrestaShop, configurations nginx, Apache et IIS, fichiers de verrouillage, fichiers Terraform) et dans `internal/vulns/testdata/` (fiches OSV). Les certificats sont générés pendant les tests. Les tests n'utilisent jamais le réseau : `db update` et `--online` sont testés contre des serveurs `httptest` locaux.

## Licence

MIT, voir [LICENSE](LICENSE). Les composants tiers sont listés dans [NOTICE](NOTICE) : osv-scalibr et les bibliothèques OSV sont sous licence Apache 2.0, compatible avec la licence MIT de cet outil.

---

Cet outil voit l'intérieur de votre serveur. Pour voir ce qu'Internet en voit, lancez l'audit externe gratuit : <https://attackscout.com/?utm_source=cli&utm_medium=cli&utm_campaign=attackscout-cli>
