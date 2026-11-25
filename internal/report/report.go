// Package report writes the scan result as text or JSON, in English or French.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/attackscout/attackscout-cli/internal/i18n"
	"github.com/attackscout/attackscout-cli/internal/inventory"
	"github.com/attackscout/attackscout-cli/internal/scan"
	"github.com/attackscout/attackscout-cli/internal/vulns"
)

// AuditURL is the free external audit, shown at the end of every report.
const AuditURL = "https://attackscout.com/?utm_source=cli&utm_medium=cli&utm_campaign=attackscout-cli"

// maxDeps is the number of plain dependencies listed in the text report.
const maxDeps = 15

// Counts returns the number of findings per severity.
func Counts(fs []scan.Finding) map[string]int {
	out := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	for _, f := range fs {
		out[f.Severity.String()]++
	}
	return out
}

func cveLabel(it scan.Item, lang string) string {
	switch {
	case it.CVE != "checked":
		return i18n.M("report.cve.notchecked").Render(lang)
	case len(it.Vulns) == 0:
		return i18n.M("report.cve.ok").Render(lang)
	}
	return i18n.M("report.cve.count", len(it.Vulns)).Render(lang)
}

// Text writes the human report.
func Text(w io.Writer, r scan.Report, version, lang string) error {
	t := func(key string, args ...any) string { return i18n.M(key, args...).Render(lang) }
	var b strings.Builder
	fmt.Fprintln(&b, t("report.title", version))
	if r.CVEMode == "online" {
		fmt.Fprintln(&b, t("report.network.on"))
	} else {
		fmt.Fprintln(&b, t("report.network.off"))
	}
	for _, kv := range [][2]string{{"root", r.Root}, {"nginx", r.Nginx}, {"apache", r.Apache}} {
		if kv[1] != "" {
			fmt.Fprintf(&b, "%s: %s\n", kv[0], kv[1])
		}
	}

	fmt.Fprintf(&b, "\n%s\n", t("report.checks"))
	for _, c := range r.Checks {
		line := fmt.Sprintf("  [%-14s] %s", t("status."+string(c.Status)), t("check."+c.ID))
		if !c.Note.IsZero() {
			line += " - " + c.Note.Render(lang)
		}
		fmt.Fprintln(&b, line)
	}

	if len(r.Items) > 0 {
		fmt.Fprintf(&b, "\n%s\n", t("report.components"))
		hidden := 0
		shown := 0
		for _, it := range r.Items {
			if it.Kind == inventory.KindDependency && len(it.Vulns) == 0 {
				if shown >= maxDeps {
					hidden++
					continue
				}
				shown++
			}
			ver := it.Version
			if ver == "" {
				ver = "?"
			}
			eco := it.Ecosystem
			if eco == "" {
				eco = "-"
			}
			fmt.Fprintf(&b, "  %-18s %-32s %-14s %-9s %-20s %s\n", it.Kind, it.Name, ver, eco,
				t("report.kv", t("report.certainty"), t("certainty."+it.Certainty())), cveLabel(it, lang))
		}
		if hidden > 0 {
			fmt.Fprintf(&b, "  %s\n", t("report.more-deps", hidden))
		}
	}

	fmt.Fprintf(&b, "\n%s\n", t("report.findings"))
	if len(r.Findings) == 0 {
		fmt.Fprintf(&b, "  %s\n", t("report.none"))
	}
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "  [%s] %s: %s\n", t("sev."+f.Severity.String()), f.ID, f.Title.Render(lang))
		if f.Path != "" {
			fmt.Fprintf(&b, "      %s\n", f.Path)
		}
		if f.Certainty != "" {
			fmt.Fprintf(&b, "      %s\n", t("report.kv", t("report.certainty"), t("certainty."+f.Certainty)))
		}
		if !f.Fix.IsZero() {
			fmt.Fprintf(&b, "      %s\n", t("report.kv", t("report.fix"), f.Fix.Render(lang)))
		}
	}
	c := Counts(r.Findings)
	fmt.Fprintf(&b, "\n%s\n\n%s\n%s\n", t("report.summary", c["critical"], c["high"], c["medium"], c["low"], c["info"]),
		t("report.external"), AuditURL)
	_, err := io.WriteString(w, b.String())
	return err
}

type jsonCheck struct {
	ID     string      `json:"id"`
	Name   string      `json:"name"`
	Status scan.Status `json:"status"`
	Note   string      `json:"note,omitempty"`
}

type jsonComponent struct {
	inventory.Component
	Certainty string       `json:"certainty"`
	CVEStatus string       `json:"cve_status"`
	Vulns     []vulns.Vuln `json:"vulnerabilities,omitempty"`
}

type jsonFinding struct {
	ID        string               `json:"id"`
	Check     string               `json:"check"`
	Severity  string               `json:"severity"`
	Message   string               `json:"message"`
	Fix       string               `json:"fix,omitempty"`
	Path      string               `json:"path,omitempty"`
	Certainty string               `json:"certainty,omitempty"`
	Component *inventory.Component `json:"component,omitempty"`
	Vuln      *vulns.Vuln          `json:"vulnerability,omitempty"`
}

type jsonReport struct {
	Tool          string          `json:"tool"`
	Version       string          `json:"version"`
	Lang          string          `json:"lang"`
	Generated     string          `json:"generated"`
	NetworkUsed   bool            `json:"network_used"`
	CVEMode       string          `json:"cve_mode"`
	EOLDataDate   string          `json:"eol_data_date"`
	Root          string          `json:"root,omitempty"`
	Nginx         string          `json:"nginx,omitempty"`
	Apache        string          `json:"apache,omitempty"`
	Checks        []jsonCheck     `json:"checks"`
	Components    []jsonComponent `json:"components"`
	Findings      []jsonFinding   `json:"findings"`
	Summary       map[string]int  `json:"summary"`
	Unchecked     []string        `json:"cve_unchecked_ecosystems,omitempty"`
	ReadErrors    []string        `json:"read_errors,omitempty"`
	ExternalAudit string          `json:"external_audit"`
}

// JSON writes the machine report.
func JSON(w io.Writer, r scan.Report, version, lang string) error {
	out := jsonReport{Tool: "attackscout-cli", Version: version, Lang: lang, Generated: r.Generated.Format("2006-01-02T15:04:05Z"),
		NetworkUsed: r.CVEMode == "online", CVEMode: r.CVEMode, EOLDataDate: r.EOLDate,
		Root: r.Root, Nginx: r.Nginx, Apache: r.Apache, Summary: Counts(r.Findings), Unchecked: r.Unchecked,
		ReadErrors: r.ReadErrors, ExternalAudit: AuditURL,
		Checks: []jsonCheck{}, Components: []jsonComponent{}, Findings: []jsonFinding{}}
	for _, c := range r.Checks {
		out.Checks = append(out.Checks, jsonCheck{ID: c.ID, Name: i18n.M("check." + c.ID).Render(lang), Status: c.Status, Note: c.Note.Render(lang)})
	}
	for _, it := range r.Items {
		out.Components = append(out.Components, jsonComponent{Component: it.Component, Certainty: it.Certainty(), CVEStatus: it.CVE, Vulns: it.Vulns})
	}
	for _, f := range r.Findings {
		out.Findings = append(out.Findings, jsonFinding{ID: f.ID, Check: f.Check, Severity: f.Severity.String(),
			Message: f.Title.Render(lang), Fix: f.Fix.Render(lang), Path: f.Path, Certainty: f.Certainty,
			Component: f.Component, Vuln: f.Vuln})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
