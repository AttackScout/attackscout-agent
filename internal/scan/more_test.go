package scan

import (
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/attackscout/attackscout-agent/internal/i18n"
	"github.com/attackscout/attackscout-agent/internal/inventory"
	"github.com/attackscout/attackscout-agent/internal/vulns"
)

func TestCheckPHPInfo(t *testing.T) {
	fs := CheckPHPInfo(filepath.Join(td, "wordpress-phpinfo"))
	if len(fs) != 1 || fs[0].ID != "phpinfo-exposed" || !strings.HasSuffix(filepath.ToSlash(fs[0].Path), "tools/check.php") || fs[0].Severity != Medium {
		t.Fatalf("%+v", fs)
	}
	if !i18n.Has("phpinfo.found") || !i18n.Has("check.phpinfo") {
		t.Error("messages")
	}
	// phpinfo.php is reported by name by the sensitive-files check, not twice
	for _, f := range CheckPHPInfo(filepath.Join(td, "wordpress")) {
		if strings.HasSuffix(f.Path, "phpinfo.php") {
			t.Error("reported twice")
		}
	}
}

func TestWPConfigGroupWritable(t *testing.T) {
	fsys := fstest.MapFS{"wp-config.php": {Mode: 0o660}, "other.php": {Mode: 0o660}}
	fs := CheckPermsFS(fsys, "/srv")
	if len(fs) != 1 || fs[0].ID != "perm-wpconfig-group-writable" || fs[0].Severity != Low {
		t.Fatalf("%+v", fs)
	}
	if fs := CheckPermsFS(fstest.MapFS{"wp-config.php": {Mode: 0o640}}, "/srv"); len(fs) != 0 {
		t.Fatalf("%+v", fs)
	}
}

func TestApplyKEV(t *testing.T) {
	v := vulns.Vuln{ID: "GHSA-1", Aliases: []string{"CVE-2021-44228"}, Severity: "medium"}
	comp := inventory.Component{Name: "log4j-core", Version: "2.14.1"}
	fs := []Finding{{ID: "vulnerable-component", Severity: Medium, Vuln: &v, Component: &comp, Title: i18n.M("cve.title", "a", "b", "c", "d", "e")}, {ID: "other"}}
	items := []Item{{Component: comp, Vulns: []vulns.Vuln{v}}}
	if ApplyKEV(fs, items, nil) != 0 {
		t.Error("nil list")
	}
	kev, _ := vulns.ParseKEV([]byte(`{"vulnerabilities":[{"cveID":"CVE-2021-44228","dateAdded":"2021-12-10","knownRansomwareCampaignUse":"Known"}]}`))
	if n := ApplyKEV(fs, items, kev); n != 1 {
		t.Fatal(n)
	}
	if fs[0].Severity != Critical || !fs[0].Vuln.KEV || !fs[0].Vuln.Ransomware || !items[0].Vulns[0].KEV {
		t.Errorf("%+v", fs[0])
	}
	if !strings.Contains(fs[0].Title.Render("en"), "CISA KEV since 2021-12-10") || !strings.Contains(fs[0].Title.Render("fr"), "KEV") {
		t.Error(fs[0].Title.Render("en"))
	}
}
