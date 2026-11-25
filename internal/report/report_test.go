package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/attackscout/attackscout-cli/internal/i18n"
	"github.com/attackscout/attackscout-cli/internal/inventory"
	"github.com/attackscout/attackscout-cli/internal/scan"
	"github.com/attackscout/attackscout-cli/internal/vulns"
)

func sample() scan.Report {
	aws := inventory.Component{Kind: inventory.KindTerraformProvider, Name: "hashicorp/aws", Version: "5.31.0", Ecosystem: "Go", Package: "github.com/hashicorp/terraform-provider-aws", Source: "/srv/infra/.terraform.lock.hcl", Exact: true}
	v := vulns.Vuln{ID: "GO-2099-0001", Aliases: []string{"CVE-2099-0001"}, Score: 10, Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", Severity: "critical", Fixed: "5.40.0"}
	items := []scan.Item{
		{Component: inventory.Component{Kind: inventory.KindRuntime, Name: "PHP", Version: "8.1.2", Source: "php -v", Exact: true}, CVE: "not_checked"},
		{Component: aws, CVE: "checked", Vulns: []vulns.Vuln{v}},
		{Component: inventory.Component{Kind: inventory.KindCMSPlugin, Name: "Hello Forms"}, CVE: "not_checked"},
	}
	for i := 0; i < 20; i++ {
		items = append(items, scan.Item{Component: inventory.Component{Kind: inventory.KindDependency, Name: "dep", Version: "1.0.0", Ecosystem: "npm", Exact: true}, CVE: "checked"})
	}
	return scan.Report{
		Root: "/var/www/site", Nginx: "/etc/nginx", EOLDate: "2026-11-25", CVEMode: "offline",
		Generated: time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC),
		Checks: []scan.Check{
			{ID: "end-of-life", Status: scan.Fail, Note: i18n.M("note.eol.date", "2026-11-25")},
			{ID: "permissions", Status: scan.NotApplicable, Note: i18n.M("note.perms.windows")},
			{ID: "certificates", Status: scan.NotChecked, Note: i18n.M("note.cert.none")},
			{ID: "sensitive-files", Status: scan.Pass},
		},
		Items: items,
		Findings: []scan.Finding{
			{ID: "vulnerable-component", Check: "vulnerabilities", Severity: scan.Critical, Title: i18n.M("cve.title", "hashicorp/aws", "5.31.0", "CVE-2099-0001", "10.0", ""),
				Fix: i18n.M("cve.fix", "hashicorp/aws", "5.40.0"), Path: aws.Source, Component: &aws, Vuln: &v, Certainty: "high"},
			{ID: "php-version", Check: "end-of-life", Severity: scan.Info, Title: i18n.M("eol.supported", "PHP", "8.3.1", "8.3")},
		},
	}
}

func TestText(t *testing.T) {
	var b bytes.Buffer
	if err := Text(&b, sample(), "0.1.0", "en"); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"AttackScout CLI 0.1.0", "Network: nothing was sent", "[not applicable", "[not checked", "[pass", "[fail",
		"hashicorp/aws", "certainty: high", "1 CVE", "CVEs not checked", "fix: Upgrade hashicorp/aws to 5.40.0 or later",
		"[CRITICAL] vulnerable-component", "... and 5 more dependencies", "Summary: 1 critical, 0 high, 0 medium, 0 low, 1 info", AuditURL} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if !strings.HasSuffix(strings.TrimSpace(out), AuditURL) {
		t.Error("the report must end with the external audit link")
	}
	b.Reset()
	r := sample()
	r.CVEMode = "online"
	r.Findings = nil
	if err := Text(&b, r, "0.1.0", "fr"); err != nil {
		t.Fatal(err)
	}
	out = b.String()
	for _, want := range []string{"analyse locale", "Réseau : --online", "[non applicable", "Fin de vie", "certitude : élevée", "aucune CVE connue", "Aucun constat.", "audit externe gratuit"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestJSON(t *testing.T) {
	var b bytes.Buffer
	if err := JSON(&b, sample(), "0.1.0", "fr"); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["external_audit"] != AuditURL || got["network_used"] != false || got["lang"] != "fr" || got["eol_data_date"] != "2026-11-25" {
		t.Errorf("%v", got)
	}
	checks := got["checks"].([]any)
	if c := checks[1].(map[string]any); c["status"] != "not_applicable" || c["name"] != "Droits des fichiers" {
		t.Errorf("%v", c)
	}
	f := got["findings"].([]any)[0].(map[string]any)
	if f["severity"] != "critical" || f["certainty"] != "high" || !strings.Contains(f["fix"].(string), "5.40.0") {
		t.Errorf("%v", f)
	}
	vuln := f["vulnerability"].(map[string]any)
	if vuln["cvss_score"] != 10.0 || vuln["fixed"] != "5.40.0" {
		t.Errorf("%v", vuln)
	}
	comp := got["components"].([]any)[1].(map[string]any)
	if comp["cve_status"] != "checked" || comp["certainty"] != "high" || comp["package"] != "github.com/hashicorp/terraform-provider-aws" {
		t.Errorf("%v", comp)
	}
	b.Reset()
	if err := JSON(&b, scan.Report{}, "0.1.0", "en"); err != nil || !strings.Contains(b.String(), `"findings": []`) {
		t.Error("empty lists must be [] not null")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestWriteError(t *testing.T) {
	if Text(failWriter{}, sample(), "x", "en") == nil {
		t.Error("write error lost")
	}
}
