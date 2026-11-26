package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/attackscout/attackscout-agent/internal/i18n"
	"github.com/attackscout/attackscout-agent/internal/inventory"
	"github.com/attackscout/attackscout-agent/internal/scan"
	"github.com/attackscout/attackscout-agent/internal/vulns"
)

func TestSARIF(t *testing.T) {
	r := sample()
	r.Root = "/var/www/site"
	comp := inventory.Component{Name: "lodash", Version: "4.17.20"}
	r.Findings = append(r.Findings,
		scan.Finding{ID: "vulnerable-component", Check: "vulnerabilities", Severity: scan.Critical, Path: "/var/www/site/package-lock.json",
			Title: i18n.M("cve.title", "lodash", "4.17.20", "CVE-2021-23337", "7.2", "x"), Fix: i18n.M("cve.fix", "lodash", "4.17.21"), Component: &comp,
			Vuln: &vulns.Vuln{ID: "GHSA-35jh-r3h4-6jhm", Aliases: []string{"CVE-2021-23337"}, Score: 7.2, Vector: "CVSS:3.1/x", Fixed: "4.17.21",
				URL: vulns.AdvisoryURL("GHSA-35jh-r3h4-6jhm"), KEV: true, Summary: "Command injection"}},
		scan.Finding{ID: "directory-listing", Check: "web-server", Severity: scan.Medium, Path: "/etc/nginx/nginx.conf", Title: i18n.M("web.nginx-autoindex")},
		scan.Finding{ID: "server-tokens", Check: "web-server", Severity: scan.Low, Title: i18n.M("web.nginx-autoindex")},
	)
	var b bytes.Buffer
	if err := SARIF(&b, r, "0.2.0", "en"); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(b.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 || log.Runs[0].Tool.Driver.Name != "attackscout-agent" {
		t.Fatalf("%+v", log)
	}
	byRule := map[string]sarifResult{}
	for _, res := range log.Runs[0].Results {
		byRule[res.RuleID] = res
		if len(res.Locations) != 1 || res.Fingerprints["attackscoutFinding/v1"] == "" {
			t.Errorf("%+v", res)
		}
	}
	cve, ok := byRule["CVE-2021-23337"]
	if !ok || cve.Level != "error" || cve.Locations[0].Physical.Artifact.URI != "package-lock.json" ||
		cve.Properties["fixed_version"] != "4.17.21" || cve.Properties["known_exploited"] != true {
		t.Errorf("%+v", cve)
	}
	if byRule["directory-listing"].Level != "warning" || byRule["server-tokens"].Level != "note" || byRule["server-tokens"].Locations[0].Physical.Artifact.URI != "." {
		t.Errorf("%+v", byRule)
	}
	if byRule["directory-listing"].Locations[0].Physical.Artifact.URI != "/etc/nginx/nginx.conf" {
		t.Error("a path outside the root is kept absolute")
	}
	for _, rule := range log.Runs[0].Tool.Driver.Rules {
		if rule.Properties["security-severity"] == nil {
			t.Errorf("%s without security-severity", rule.ID)
		}
		if rule.ID == "CVE-2021-23337" && (rule.Properties["security-severity"] != "9.5" || !strings.Contains(rule.HelpURI, "GHSA-35jh") || rule.ShortDescription.Text != "Command injection") {
			t.Errorf("%+v", rule)
		}
	}
	if strings.Contains(b.String(), AuditURL) || strings.Contains(b.String(), "php-version") {
		t.Error("no audit link and no info findings in SARIF")
	}
	if SARIF(failWriter{}, r, "x", "en") == nil {
		t.Error("write error")
	}
	if securitySeverity(scan.Finding{Severity: scan.High, Vuln: &vulns.Vuln{Score: 7.5}}) != "7.5" {
		t.Error("CVSS score used when not exploited")
	}
}

func TestTextAuditLinkOption(t *testing.T) {
	var with, without bytes.Buffer
	_ = Text(&with, sample(), "0.2.0", "en", true)
	_ = Text(&without, sample(), "0.2.0", "en", false)
	if !strings.Contains(with.String(), AuditURL) || strings.Contains(without.String(), "attackscout.com") {
		t.Error("audit link option")
	}
	if !strings.Contains(AuditURL, "/en?") || !strings.Contains(AuditURL, "utm_source=attackscout-agent") {
		t.Error(AuditURL)
	}
	if !strings.Contains(with.String(), "CISA KEV list not downloaded") {
		t.Error("KEV hint")
	}
}
