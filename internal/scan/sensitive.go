package scan

import (
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/attackscout/attackscout-agent/internal/i18n"
)

const (
	maxDepth = 10
	maxFiles = 200000
)

// skipDirs are not walked into (still checked themselves).
var skipDirs = map[string]bool{"node_modules": true, "vendor": true}

type sensitiveRule struct {
	id       string
	severity Severity
	what     string // i18n key of the file kind
	fix      string // i18n key of the advice
}

var (
	ruleEnv       = sensitiveRule{"sensitive-env", Critical, "what.env", "fix.sensitive-env"}
	ruleEnvSample = sensitiveRule{"sensitive-env-sample", Low, "what.env-sample", "fix.sensitive-env-sample"}
	ruleVCS       = sensitiveRule{"sensitive-vcs", High, "what.vcs", "fix.sensitive-vcs"}
	ruleBackup    = sensitiveRule{"sensitive-backup", High, "what.backup", "fix.sensitive-backup"}
	ruleDump      = sensitiveRule{"sensitive-backup", Critical, "what.dump", "fix.sensitive-dump"}
	rulePHPInfo   = sensitiveRule{"sensitive-phpinfo", Medium, "what.phpinfo", "fix.sensitive-phpinfo"}
	ruleDSStore   = sensitiveRule{"sensitive-ds-store", Low, "what.ds-store", "fix.sensitive-ds-store"}
	ruleComposer  = sensitiveRule{"sensitive-composer", Low, "what.composer", "fix.sensitive-composer"}
	ruleAuthJSON  = sensitiveRule{"sensitive-auth-json", Critical, "what.auth-json", "fix.sensitive-auth-json"}
	ruleLog       = sensitiveRule{"sensitive-log", Medium, "what.log", "fix.sensitive-log"}
	ruleHtpasswd  = sensitiveRule{"sensitive-htpasswd", Medium, "what.htpasswd", "fix.sensitive-htpasswd"}
	ruleKey       = sensitiveRule{"sensitive-private-key", Critical, "what.key", "fix.sensitive-private-key"}
	ruleTFState   = sensitiveRule{"sensitive-tfstate", Critical, "what.tfstate", "fix.sensitive-tfstate"}
)

var backupSuffixes = []string{".sql", ".sql.gz", ".sql.zip", ".dump", ".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".7z", ".rar", ".bak", ".old", ".orig", ".save", ".swp", "~"}

// classify returns the rule matching a file or directory name, if any.
// atRoot tells whether the entry sits directly in the web root.
func classify(name string, dir, atRoot bool) *sensitiveRule {
	lower := strings.ToLower(name)
	if dir {
		switch lower {
		case ".git", ".svn", ".hg", ".bzr":
			return &ruleVCS
		}
		return nil
	}
	switch {
	case lower == ".env.example" || lower == ".env.sample" || lower == ".env.dist":
		return &ruleEnvSample
	case lower == ".env" || strings.HasPrefix(lower, ".env."):
		return &ruleEnv
	case lower == "auth.json":
		return &ruleAuthJSON
	case lower == "phpinfo.php" || lower == "info.php" || lower == "php_info.php":
		return &rulePHPInfo
	case lower == ".ds_store":
		return &ruleDSStore
	case atRoot && (lower == "composer.json" || lower == "composer.lock"):
		return &ruleComposer
	case lower == ".htpasswd":
		return &ruleHtpasswd
	case lower == "terraform.tfstate" || strings.HasSuffix(lower, ".tfstate") || strings.HasSuffix(lower, ".tfstate.backup"):
		return &ruleTFState
	case lower == "debug.log" || lower == "error_log" || strings.HasSuffix(lower, ".log"):
		return &ruleLog
	case lower == "id_rsa" || lower == "id_ed25519" || strings.HasSuffix(lower, ".key") || strings.HasSuffix(lower, ".pem") || strings.HasSuffix(lower, ".p12") || strings.HasSuffix(lower, ".pfx"):
		return &ruleKey
	}
	for _, s := range backupSuffixes {
		if strings.HasSuffix(lower, s) {
			if strings.Contains(lower, ".sql") || strings.HasSuffix(lower, ".dump") || strings.Contains(lower, "wp-config") || strings.Contains(lower, ".env") {
				return &ruleDump
			}
			return &ruleBackup
		}
	}
	return nil
}

// CheckSensitive reports sensitive files in the web root. It reads names
// only: the content of a file is never opened.
func CheckSensitive(root string) []Finding {
	var out []Finding
	count := 0
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || path == root {
			return nil
		}
		count++
		if count > maxFiles {
			return fs.SkipAll
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		depth := strings.Count(rel, "/")
		if r := classify(d.Name(), d.IsDir(), depth == 0); r != nil {
			out = append(out, Finding{ID: r.id, Severity: r.severity, Path: path,
				Title: i18n.M("sensitive.found", i18n.M(r.what), rel),
				Fix:   i18n.M(r.fix)})
			if d.IsDir() {
				return fs.SkipDir
			}
		}
		if d.IsDir() && (skipDirs[d.Name()] || depth >= maxDepth) {
			return fs.SkipDir
		}
		return nil
	})
	return out
}
