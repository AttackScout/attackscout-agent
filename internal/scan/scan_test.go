package scan

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/attackscout/attackscout-agent/internal/eol"
	"github.com/attackscout/attackscout-agent/internal/i18n"
	"github.com/attackscout/attackscout-agent/internal/inventory"
	"github.com/attackscout/attackscout-agent/internal/vulns"
)

const td = "../../testdata"

var now = time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

func byID(fs []Finding) map[string][]Finding {
	out := map[string][]Finding{}
	for _, f := range fs {
		out[f.ID] = append(out[f.ID], f)
	}
	return out
}

// copyDir copies a fixture so that tests can add files git cannot hold (.git).
func copyDir(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o750)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func TestParseSeverity(t *testing.T) {
	for in, want := range map[string]Severity{"high": High, " CRITICAL ": Critical, "info": Info, "none": -1, "": -1} {
		got, err := ParseSeverity(in)
		if err != nil || got != want {
			t.Errorf("%q: %v %v", in, got, err)
		}
	}
	if _, err := ParseSeverity("severe"); err == nil {
		t.Error("unknown severity accepted")
	}
	if b, _ := Medium.MarshalText(); string(b) != "medium" {
		t.Error(string(b))
	}
}

func TestSensitive(t *testing.T) {
	root := copyDir(t, filepath.Join(td, "wordpress"))
	for _, d := range []string{".git", filepath.Join("node_modules", "x"), filepath.Join("sub", ".svn")} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"auth.json", ".htpasswd", "site.key", "old.tar.gz", "terraform.tfstate", filepath.Join("sub", "composer.json"), filepath.Join("node_modules", "x", "backup.zip"), "notes.txt"} {
		if err := os.WriteFile(filepath.Join(root, f), []byte("secret-value"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got := byID(CheckSensitive(root))
	want := map[string]int{"sensitive-env": 1, "sensitive-env-sample": 1, "sensitive-vcs": 2, "sensitive-backup": 4,
		"sensitive-phpinfo": 1, "sensitive-ds-store": 1, "sensitive-composer": 1, "sensitive-log": 1,
		"sensitive-auth-json": 1, "sensitive-htpasswd": 1, "sensitive-private-key": 1, "sensitive-tfstate": 1}
	for id, n := range want {
		if len(got[id]) != n {
			t.Errorf("%s: %d findings, want %d", id, len(got[id]), n)
		}
	}
	for _, f := range got["sensitive-backup"] {
		dump := strings.Contains(f.Path, ".sql") || strings.Contains(f.Path, "wp-config")
		if dump != (f.Severity == Critical) {
			t.Errorf("%s: severity %v", f.Path, f.Severity)
		}
	}
	for _, fs := range got {
		for _, f := range fs {
			for _, lang := range []string{"en", "fr"} {
				if s := f.Title.Render(lang) + f.Fix.Render(lang); strings.Contains(s, "secret-value") || strings.Contains(s, "not-a-real") {
					t.Fatalf("file content leaked: %s", s)
				}
			}
		}
	}
	if len(CheckSensitive(t.TempDir())) != 0 {
		t.Error("empty root")
	}
}

func TestPermsFS(t *testing.T) {
	m := fstest.MapFS{
		".":                    {Mode: fs.ModeDir | 0o755},
		"wp-config.php":        {Mode: 0o644},
		".env":                 {Mode: 0o640},
		"index.php":            {Mode: 0o666},
		"uploads":              {Mode: fs.ModeDir | 0o777},
		"cache":                {Mode: fs.ModeDir | 0o773},
		"tmp":                  {Mode: fs.ModeDir | fs.ModeSticky | 0o777},
		"tmp2":                 {Mode: fs.ModeDir | fs.ModeSticky | 0o773},
		"link":                 {Mode: fs.ModeSymlink | 0o777},
		"node_modules":         {Mode: fs.ModeDir | 0o755},
		"node_modules/x.js":    {Mode: 0o666},
		"sites/default/ok.php": {Mode: 0o644},
	}
	got := byID(CheckPermsFS(m, "/var/www/site"))
	for id, n := range map[string]int{"perm-file-world-writable": 1, "perm-dir-777": 2, "perm-dir-world-writable": 1, "perm-secret-world-readable": 1} {
		if len(got[id]) != n {
			t.Errorf("%s: %d, want %d (%v)", id, len(got[id]), n, got[id])
		}
	}
	if p := got["perm-secret-world-readable"][0].Path; p != filepath.Join("/var/www/site", "wp-config.php") {
		t.Error(p)
	}
	// cap: 25 world-writable files give 20 findings and one summary
	many := fstest.MapFS{".": {Mode: fs.ModeDir | 0o755}}
	for i := 0; i < 25; i++ {
		many[strings.Repeat("f", i+1)] = &fstest.MapFile{Mode: 0o666}
	}
	fs := CheckPermsFS(many, "r")
	if len(fs) != 21 || fs[20].Severity != Info || !strings.Contains(fs[20].Title.Render("en"), "5 more") {
		t.Fatalf("cap: %d findings", len(fs))
	}
	if len(CheckPerms(t.TempDir())) > 0 && os.Getenv("GOOS") == "" {
		t.Log("temp directory permissions vary by system")
	}
}

func TestWPConfig(t *testing.T) {
	root := filepath.Join(td, "wordpress")
	got := byID(CheckWPConfig(root))
	def := got["wpconfig-salt-default"]
	if len(def) != 1 || def[0].Severity != Critical || !strings.Contains(def[0].Title.Render("en"), "AUTH_KEY, SECURE_AUTH_KEY") {
		t.Fatalf("defaults: %+v", def)
	}
	miss := got["wpconfig-salt-missing"]
	if len(miss) != 1 || !strings.HasSuffix(miss[0].Title.Render("en"), "NONCE_SALT") {
		t.Fatalf("missing: %+v", miss)
	}
	for _, id := range []string{"wpconfig-debug", "wpconfig-debug-display", "wpconfig-file-edit"} {
		if len(got[id]) != 1 {
			t.Errorf("%s missing", id)
		}
	}
	all := ""
	for _, fs := range got {
		for _, f := range fs {
			all += f.Title.Render("en") + f.Title.Render("fr")
		}
	}
	for _, secret := range []string{"not-a-real-password", "k2//x", "a-long-random-value", "example_db"} {
		if strings.Contains(all, secret) {
			t.Fatalf("secret printed: %s", secret)
		}
	}

	// hardened config, one level above the web root
	dir := t.TempDir()
	web := filepath.Join(dir, "public")
	if err := os.MkdirAll(web, 0o750); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.WriteString("<?php\n")
	for _, k := range wpSalts {
		b.WriteString("define('" + k + "', 'Zx9//q/*w-" + k + "');\n")
	}
	b.WriteString("define('WP_DEBUG', 'true');\ndefine('WP_DEBUG_DISPLAY', false);\ndefine('DISALLOW_FILE_EDIT', 1);\n")
	if err := os.WriteFile(filepath.Join(dir, "wp-config.php"), []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if FindWPConfig(web) == "" {
		t.Fatal("parent wp-config.php not found")
	}
	got = byID(CheckWPConfig(web))
	if len(got) != 1 || len(got["wpconfig-debug"]) != 1 {
		t.Fatalf("hardened: %v", got)
	}
	if CheckWPConfig(t.TempDir()) != nil {
		t.Error("no wp-config")
	}
}

func TestWebNginx(t *testing.T) {
	w := LoadWebConfig(filepath.Join(td, "nginx"), "", "")
	fs, st, _ := CheckWebConfig(w)
	got := byID(fs)
	for _, id := range []string{"header-hsts-missing", "header-csp-missing", "header-frame-missing", "header-referrer-missing", "server-tokens", "directory-listing"} {
		if len(got[id]) != 1 {
			t.Errorf("%s: %d", id, len(got[id]))
		}
	}
	if len(got["header-xcto-missing"]) != 0 {
		t.Error("X-Content-Type-Options is set")
	}
	if st != Pass {
		t.Error(st)
	}
	if len(w.Certs) != 1 || w.Certs[0] != filepath.Join(td, "nginx", "certs", "example.com.pem") {
		t.Errorf("certs: %v", w.Certs)
	}
	if len(w.Roots) != 1 || w.Roots[0] != "/var/www/example.com" {
		t.Errorf("roots: %v", w.Roots)
	}
	if !strings.Contains(w.Text(), "php7.4-fpm") || strings.Contains(w.Text(), "server_tokens off") {
		t.Error("comments must be removed, enabled sites kept")
	}
	fix := got["header-hsts-missing"][0].Fix
	if !strings.Contains(fix.Render("en"), "add_header Strict-Transport-Security") || !strings.Contains(fix.Render("fr"), "Envoyez") {
		t.Error(fix.Render("en"))
	}
	hard, _, _ := CheckWebConfig(LoadWebConfig(filepath.Join(td, "nginx-hardened"), "", ""))
	if len(hard) != 0 {
		t.Errorf("hardened nginx: %v", byID(hard))
	}
}

func TestWebApache(t *testing.T) {
	root := filepath.Join(td, "wordpress")
	w := LoadWebConfig("", filepath.Join(td, "apache"), root)
	got := byID(mustFindings(CheckWebConfig(w)))
	for _, id := range []string{"header-csp-missing", "header-xcto-missing", "header-referrer-missing", "server-tokens", "server-signature"} {
		if len(got[id]) != 1 {
			t.Errorf("%s: %d", id, len(got[id]))
		}
	}
	if len(got["header-hsts-missing"]) != 0 || len(got["header-frame-missing"]) != 0 {
		t.Error("HSTS in vhost and X-Frame-Options in .htaccess are set")
	}
	if len(got["directory-listing"]) != 2 {
		t.Errorf("Options Indexes in apache2.conf and .htaccess: %d", len(got["directory-listing"]))
	}
	if len(w.Certs) != 1 || len(w.Roots) != 1 {
		t.Errorf("%v %v", w.Certs, w.Roots)
	}
	if hard := mustFindings(CheckWebConfig(LoadWebConfig("", filepath.Join(td, "apache-hardened"), ""))); len(hard) != 0 {
		t.Errorf("hardened apache: %v", byID(hard))
	}
	// .htaccess alone counts as Apache configuration
	alone := LoadWebConfig("", "", root)
	if len(alone.Apache) != 1 {
		t.Fatal(".htaccess alone")
	}
	if fs := mustFindings(CheckWebConfig(alone)); fs[0].Path != filepath.Join(root, ".htaccess") {
		t.Error(fs[0].Path)
	}
	if !optionsIndexes("All") || optionsIndexes("-Indexes FollowSymLinks") {
		t.Error("optionsIndexes")
	}
}

func mustFindings(fs []Finding, _ Status, _ i18n.Msg) []Finding { return fs }

func TestWebIIS(t *testing.T) {
	root := t.TempDir()
	data, err := os.ReadFile(filepath.Join(td, "iis", "web.config"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "web.config"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	w := LoadWebConfig("", "", root)
	if w.IIS == nil || w.IIS.Err != nil {
		t.Fatalf("%+v", w.IIS)
	}
	got := byID(mustFindings(CheckWebConfig(w)))
	for _, id := range []string{"header-hsts-missing", "server-tokens", "x-powered-by", "directory-listing"} {
		if len(got[id]) != 1 {
			t.Errorf("%s: %d", id, len(got[id]))
		}
	}
	for _, id := range []string{"header-csp-missing", "header-xcto-missing", "header-frame-missing", "header-referrer-missing"} {
		if len(got[id]) != 0 {
			t.Errorf("%s should be set (location and frame-ancestors)", id)
		}
	}
	hard := ParseWebConfig(filepath.Join(td, "iis", "web-hardened.config"))
	if fs := mustFindings(CheckWebConfig(WebConfig{IIS: hard})); len(fs) != 0 {
		t.Errorf("hardened IIS: %v", byID(fs))
	}
	bad := LoadWebConfig("", "", filepath.Join(td, "iis-bad"))
	fs, st, note := CheckWebConfig(bad)
	if st != NotChecked || len(fs) != 0 || !strings.Contains(note.Render("fr"), "non vérifiés") {
		t.Fatalf("unparsable web.config: %v %v", st, note.Render("en"))
	}
	bad.Nginx = []ConfFile{{Path: "n", Text: "server_tokens off;"}}
	if _, st, note := CheckWebConfig(bad); st != Pass || note.IsZero() {
		t.Error("nginx checked, IIS noted")
	}
	if c := ParseWebConfig(filepath.Join(td, "iis", "missing.config")); c.Err == nil {
		t.Error("missing file")
	}
	if _, st, _ := CheckWebConfig(WebConfig{}); st != NotChecked {
		t.Error("no configuration must be not_checked")
	}
}

func writeCert(t *testing.T, dir, name string, notAfter time.Time, key any, pub any, extra ...[]byte) string {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		DNSNames: []string{name}, NotBefore: notAfter.AddDate(-1, 0, 0), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	for _, e := range extra {
		data = append(data, e...)
	}
	p := filepath.Join(dir, name+".pem")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCerts(t *testing.T) {
	dir := t.TempDir()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	weak, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // weak key on purpose
	if err != nil {
		t.Fatal(err)
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("never-printed")})
	expiredLeaf := writeCert(t, dir, "expired.example.com", now.AddDate(0, 0, -3), rsaKey, &rsaKey.PublicKey)
	soon := writeCert(t, dir, "soon.example.com", now.AddDate(0, 0, 10), ec, &ec.PublicKey, keyPEM)
	ok := writeCert(t, dir, "ok.example.com", now.AddDate(0, 6, 0), rsaKey, &rsaKey.PublicKey)
	weakP := writeCert(t, dir, "weak.example.com", now.AddDate(1, 0, 0), weak, &weak.PublicKey)
	expiredData, _ := os.ReadFile(expiredLeaf)
	okData, _ := os.ReadFile(ok)
	chain := filepath.Join(dir, "chain.pem")
	if err := os.WriteFile(chain, append(okData, expiredData...), 0o600); err != nil {
		t.Fatal(err)
	}
	noPEM := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(noPEM, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	got := byID(CheckCerts([]string{expiredLeaf, soon, ok, weakP, chain, noPEM, filepath.Join(dir, "missing.pem")}, now))
	if f := got["cert-expired"]; len(f) != 1 || f[0].Severity != Critical || !strings.Contains(f[0].Title.Render("en"), "expired on") {
		t.Errorf("expired: %v", f)
	}
	if f := got["cert-expiring"]; len(f) != 1 || f[0].Severity != High || !strings.Contains(f[0].Title.Render("fr"), "10 jours") {
		t.Errorf("expiring: %v", f)
	}
	if len(got["cert-valid"]) != 3 || len(got["cert-chain-expired"]) != 1 || len(got["cert-weak-key"]) != 1 || len(got["cert-unreadable"]) != 2 {
		t.Errorf("%v", got)
	}
	for _, fs := range got {
		for _, f := range fs {
			if strings.Contains(f.Title.Render("en"), "never-printed") {
				t.Fatal("key printed")
			}
		}
	}
	if b, weak := keyStrength(&x509.Certificate{}); b != 0 || weak {
		t.Error("unknown key type")
	}
}

type fakeMatcher struct{ r vulns.Result }

func (f fakeMatcher) Match(context.Context, []inventory.Component) vulns.Result { return f.r }

func TestCheckEOL(t *testing.T) {
	cs := []inventory.Component{
		{Product: "php", Name: "PHP", Version: "8.1.2", Exact: true},
		{Product: "php", Name: "PHP", Version: "8.2.1", Exact: true},
		{Product: "php", Name: "PHP", Version: "8.3", Exact: false},
		{Product: "nextjs", Name: "Next.js", Version: "13.5.0", Exact: true},
		{Product: "react", Name: "React", Version: "19.0.0", Exact: true},
		{Product: "php", Name: "PHP", Version: "12.0.0", Exact: true},
		{Name: "lodash", Version: "1.0.0"},
		{Product: "php", Name: "PHP"},
	}
	fs, n := CheckEOL(cs, eol.Default(), now)
	if n != 6 {
		t.Fatalf("looked up %d", n)
	}
	got := byID(fs)
	if len(got["php-eol"]) != 1 || len(got["php-eol-soon"]) != 1 || len(got["php-patch-behind"]) != 1 || len(got["nextjs-eol"]) != 1 {
		t.Fatalf("%v", got)
	}
	if len(got["php-version"]) != 2 || len(got["react-version"]) != 1 {
		t.Fatalf("info: %v", got)
	}
	if got["php-eol"][0].Certainty != "high" || got["php-eol"][0].Fix.IsZero() {
		t.Error("certainty and fix")
	}
	if !strings.Contains(got["php-eol"][0].Title.Render("fr"), "fin de vie") {
		t.Error(got["php-eol"][0].Title.Render("fr"))
	}
}

func TestCheckVulns(t *testing.T) {
	cs := []inventory.Component{
		{Kind: inventory.KindDependency, Name: "lodash", Version: "4.17.20", Ecosystem: "npm", Package: "lodash", Exact: true},
		{Kind: inventory.KindTerraformProvider, Name: "hashicorp/aws", Version: "5.0.0", Ecosystem: "Go", Package: "github.com/hashicorp/terraform-provider-aws"},
		{Kind: inventory.KindCMSPlugin, Name: "Hello Forms", Version: "2.3.1"},
		{Kind: inventory.KindDependency, Name: "django", Version: "3.2.0", Ecosystem: "PyPI", Package: "django", Exact: true},
	}
	ctx := context.Background()
	// no matcher
	fs0, items0, st, note, _, mode0 := CheckVulns(ctx, cs, nil)
	if st != NotChecked || len(fs0) != 0 || mode0 != "none" || !strings.Contains(note.Render("fr"), "lancez « attackscout-agent db update »") || items0[0].CVE != "not_checked" {
		t.Fatalf("no matcher: %v %s", st, note.Render("en"))
	}
	// partial, with findings
	r := vulns.Result{Mode: "offline", Checked: map[string]bool{"npm": true, "Go": true}, Reasons: map[string]string{"PyPI": "no local database"},
		DBDates: map[string]time.Time{"npm": now}, Vulns: map[int][]vulns.Vuln{
			0: {{ID: "GHSA-1", Aliases: []string{"CVE-2021-1"}, Score: 7.2, Vector: "CVSS:3.1/x", Severity: "high", Fixed: "4.17.21", Summary: "Command injection"}},
			1: {{ID: "GO-1", Severity: "critical"}, {ID: "GO-2", Severity: "low"}, {ID: "GO-3", Severity: "medium"}},
		}}
	fs, items, st, note, unchecked, mode := CheckVulns(ctx, cs, fakeMatcher{r})
	if st != Fail || mode != "offline" || len(fs) != 4 || strings.Join(unchecked, ",") != "PyPI" || !strings.Contains(note.Render("en"), "PyPI") {
		t.Fatalf("partial: %v %d %v %s", st, len(fs), unchecked, note.Render("en"))
	}
	f := fs[0]
	if f.Severity != High || f.Certainty != "high" || !strings.Contains(f.Title.Render("en"), "CVE-2021-1 (CVSS 7.2)") || !strings.Contains(f.Fix.Render("fr"), "4.17.21") {
		t.Errorf("%s / %s", f.Title.Render("en"), f.Fix.Render("fr"))
	}
	if fs[1].Certainty != "medium" || !strings.Contains(fs[1].Title.Render("en"), "CVSS ?") || !strings.Contains(fs[1].Fix.Render("en"), "No fixed version") {
		t.Errorf("%+v", fs[1])
	}
	if items[0].CVE != "checked" || items[2].CVE != "not_checked" || items[3].CVE != "not_checked" {
		t.Error("items status")
	}
	// all checked, nothing found
	clean := vulns.Result{Mode: "offline", Checked: map[string]bool{"npm": true}, DBDates: map[string]time.Time{"npm": now}}
	_, _, st, note, _, _ = CheckVulns(ctx, cs[:1], fakeMatcher{clean})
	if st != Pass || !strings.Contains(note.Render("en"), "2026-11-25") {
		t.Errorf("clean: %v %s", st, note.Render("en"))
	}
	_, _, st, note, _, _ = CheckVulns(ctx, cs[:1], fakeMatcher{vulns.Result{Mode: "online", Checked: map[string]bool{"npm": true}}})
	if st != Pass || !strings.Contains(note.Render("en"), "api.osv.dev") {
		t.Errorf("online: %v", st)
	}
	_, _, st, note, _, _ = CheckVulns(ctx, cs[:3], fakeMatcher{vulns.Result{Mode: "offline", Checked: map[string]bool{"npm": true, "Go": true}}})
	if st != Pass || !strings.Contains(note.Render("en"), "1 components") {
		t.Errorf("components without ecosystem must be noted: %v %s", st, note.Render("en"))
	}
	_, _, st, _, _, _ = CheckVulns(ctx, cs[2:3], fakeMatcher{vulns.Result{Mode: "offline"}})
	if st != NotChecked {
		t.Error("only untracked components: not checked")
	}
	_, _, st, _, _, _ = CheckVulns(ctx, cs[3:], fakeMatcher{vulns.Result{Mode: "offline", Reasons: map[string]string{"PyPI": "x"}}})
	if st != NotChecked {
		t.Error("missing database: not checked, never pass")
	}
	if _, _, st, _, _, _ := CheckVulns(ctx, nil, nil); st != NotApplicable {
		t.Error("no component")
	}
	if oldest(nil) != "?" || toSeverity("low") != Low || toSeverity("x") != Medium {
		t.Error("helpers")
	}
}

func TestRun(t *testing.T) {
	root := filepath.Join(td, "wordpress")
	r := Run(context.Background(), Options{Root: root, Projects: []string{filepath.Join(td, "project")},
		Nginx: filepath.Join(td, "nginx"), Now: now, GOOS: "windows",
		Exec: func(string, ...string) (string, error) { return "", os.ErrNotExist }})
	st := map[string]Status{}
	for _, c := range r.Checks {
		st[c.ID] = c.Status
	}
	want := map[string]Status{"end-of-life": Fail, "vulnerabilities": NotChecked, "sensitive-files": Fail,
		"permissions": NotApplicable, "wp-config": Fail, "web-server": Fail, "certificates": Fail}
	for id, s := range want {
		if st[id] != s {
			t.Errorf("%s: %s, want %s", id, st[id], s)
		}
	}
	if r.CVEMode != "none" || r.EOLDate != "2026-11-25" || len(r.Items) == 0 {
		t.Errorf("%+v", r)
	}
	for i := 1; i < len(r.Findings); i++ {
		if r.Findings[i-1].Severity < r.Findings[i].Severity {
			t.Fatal("findings must be sorted")
		}
	}
	for _, f := range r.Findings {
		if f.Check == "" {
			t.Fatalf("finding without check: %s", f.ID)
		}
	}
	// nothing given
	empty := Run(context.Background(), Options{GOOS: "linux"})
	for _, c := range empty.Checks {
		if c.Status == Pass || c.Status == Fail {
			t.Errorf("%s: %s with nothing to scan", c.ID, c.Status)
		}
	}
	// Unix permissions on a clean temporary site
	site := t.TempDir()
	if err := os.WriteFile(filepath.Join(site, "index.html"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	r = Run(context.Background(), Options{Root: site, GOOS: "linux", Now: now, Matcher: fakeMatcher{vulns.Result{Mode: "offline"}}})
	for _, c := range r.Checks {
		if c.ID == "permissions" && c.Status == NotApplicable {
			t.Error("permissions apply on Linux")
		}
		if c.ID == "wp-config" && c.Status != NotApplicable {
			t.Error("wp-config is not applicable without WordPress")
		}
	}
}

func TestHelpersScan(t *testing.T) {
	fs := []Finding{{ID: "b", Severity: Low, Path: "2"}, {ID: "b", Severity: Low, Path: "1"}, {ID: "a", Severity: Low}, {ID: "z", Severity: High}}
	Sort(fs)
	if fs[0].ID != "z" || fs[1].ID != "a" || fs[2].Path != "1" {
		t.Errorf("%v", fs)
	}
	if got := dedupe([]string{"a", "", "a", "b"}); len(got) != 2 {
		t.Error(got)
	}
	if _, err := readSmall(t.TempDir()); err == nil {
		t.Error("directory accepted")
	}
	if got := resolve("", reNginxCert, "ssl_certificate rel.pem;"); got[0] != "rel.pem" {
		t.Error(got)
	}
	if d := readConfDir(filepath.Join(td, "missing")); d != nil {
		t.Error(d)
	}
}
