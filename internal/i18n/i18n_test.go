package i18n

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestRender(t *testing.T) {
	m := M("eol.unknown", "PHP", "9.0")
	if got := m.Render("en"); !strings.Contains(got, "PHP 9.0 detected") {
		t.Error(got)
	}
	if got := m.Render("fr"); !strings.Contains(got, "PHP 9.0 détecté") {
		t.Error(got)
	}
	nested := M("sensitive.found", M("what.env"), ".env")
	if got := nested.Render("fr"); !strings.HasPrefix(got, "Fichier d'environnement sensible") {
		t.Error(got)
	}
	if M("report.none").Render("en") != "No finding." || (Msg{}).Render("en") != "" || M("no.such.key").Render("fr") != "no.such.key" {
		t.Error("plain, empty and unknown messages")
	}
	if !(Msg{}).IsZero() || M("x").IsZero() {
		t.Error("IsZero")
	}
	data, err := json.Marshal(M("report.none"))
	if err != nil || string(data) != `"No finding."` {
		t.Error(string(data), err)
	}
	if !Valid("en") || !Valid("fr") || Valid("de") || len(Langs) != 2 {
		t.Error("languages")
	}
}

// TestCatalogComplete checks that every key used in the code exists in both
// languages, with the same number of arguments.
func TestCatalogComplete(t *testing.T) {
	re := regexp.MustCompile(`"((?:eol|note|cve|sensitive|what|fix|perm|wp|cert|web|report|status|sev|certainty|check)\.[a-z0-9.-]+)"`)
	used := map[string]bool{}
	err := filepath.WalkDir("..", func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") || strings.HasSuffix(p, "catalog.go") {
			return err
		}
		data, err := os.ReadFile(p)
		for _, m := range re.FindAllStringSubmatch(string(data), -1) {
			if !strings.HasSuffix(m[1], ".") && m[1] != "web.config" {
				used[m[1]] = true
			}
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	dynamic := []string{"status.pass", "status.fail", "status.not_applicable", "status.not_checked",
		"sev.info", "sev.low", "sev.medium", "sev.high", "sev.critical", "certainty.high", "certainty.medium",
		"check.end-of-life", "check.vulnerabilities", "check.sensitive-files", "check.permissions",
		"check.wp-config", "check.web-server", "check.certificates",
		"fix.header-hsts-missing", "fix.header-csp-missing", "fix.header-xcto-missing", "fix.header-frame-missing", "fix.header-referrer-missing"}
	for _, k := range dynamic {
		used[k] = true
	}
	if len(used) < 100 {
		t.Fatalf("only %d keys found: the scan is broken", len(used))
	}
	for k := range used {
		if !Has(k) {
			t.Errorf("missing translation %q", k)
		}
	}
	verb := regexp.MustCompile(`%[-0-9]*[a-zA-Z]`)
	for k, v := range catalog {
		if len(verb.FindAllString(v[0], -1)) != len(verb.FindAllString(v[1], -1)) {
			t.Errorf("%s: arguments differ between languages", k)
		}
		if v[0] == v[1] && strings.Contains(v[0], " ") && !strings.HasPrefix(k, "fix.header.") && k != "cve.fix" {
			if strings.ContainsAny(v[0], "aeiou") && !strings.HasPrefix(k, "check.") && !strings.HasPrefix(k, "report.cve.count") {
				t.Errorf("%s: French text identical to English", k)
			}
		}
	}
}
