package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/attackscout/attackscout-agent/internal/i18n"
	"github.com/attackscout/attackscout-agent/internal/scan"
)

// ToolURL is the home page of the tool, written in SARIF files.
const ToolURL = "https://github.com/AttackScout/attackscout-agent"

// SARIF 2.1.0, the subset read by GitHub code scanning, GitLab and Azure DevOps.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription sarifText      `json:"shortDescription"`
	FullDescription  sarifText      `json:"fullDescription"`
	Help             sarifText      `json:"help"`
	HelpURI          string         `json:"helpUri,omitempty"`
	Default          sarifConfig    `json:"defaultConfiguration"`
	Properties       map[string]any `json:"properties"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID       string            `json:"ruleId"`
	Level        string            `json:"level"`
	Message      sarifText         `json:"message"`
	Locations    []sarifLocation   `json:"locations"`
	Fingerprints map[string]string `json:"partialFingerprints"`
	Properties   map[string]any    `json:"properties,omitempty"`
}

type sarifLocation struct {
	Physical sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	Artifact sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

// sarifLevel maps a severity to a SARIF level.
func sarifLevel(s scan.Severity) string {
	switch {
	case s >= scan.High:
		return "error"
	case s == scan.Medium:
		return "warning"
	}
	return "note"
}

// securitySeverity is the number GitHub uses to sort alerts (0 to 10).
func securitySeverity(f scan.Finding) string {
	if f.Vuln != nil && f.Vuln.Score > 0 && !f.Vuln.KEV {
		return strconv.FormatFloat(f.Vuln.Score, 'f', 1, 64)
	}
	return map[scan.Severity]string{scan.Critical: "9.5", scan.High: "8.0", scan.Medium: "5.5", scan.Low: "3.0", scan.Info: "0.0"}[f.Severity]
}

// sarifURI makes a path relative to the scanned root when it is inside it,
// so that code scanning can link the file of the repository.
func sarifURI(path, root string) string {
	if path == "" {
		return "."
	}
	if root != "" {
		if rel, err := filepath.Rel(root, path); err == nil && !strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel) {
			return filepath.ToSlash(rel)
		}
	}
	return filepath.ToSlash(path)
}

// SARIF writes the findings as a SARIF 2.1.0 log. Findings of severity info
// are left out: they describe the inventory, not a problem.
func SARIF(w io.Writer, r scan.Report, version, lang string) error {
	rules := map[string]sarifRule{}
	results := []sarifResult{}
	for _, f := range r.Findings {
		if f.Severity == scan.Info {
			continue
		}
		id := f.ID
		msg := f.Title.Render(lang)
		fix := f.Fix.Render(lang)
		rule := sarifRule{ID: id, Name: id, ShortDescription: sarifText{i18n.M("check." + f.Check).Render(lang)},
			FullDescription: sarifText{msg}, Help: sarifText{fix}, Default: sarifConfig{sarifLevel(f.Severity)},
			Properties: map[string]any{"tags": []string{"security", f.Check}}}
		props := map[string]any{}
		if f.Vuln != nil {
			id = f.Vuln.CVE()
			rule.ID, rule.Name, rule.HelpURI = id, id, f.Vuln.URL
			if f.Vuln.Summary != "" {
				rule.ShortDescription = sarifText{f.Vuln.Summary}
			}
			props["advisory"] = f.Vuln.URL
			props["known_exploited"] = f.Vuln.KEV
			if f.Vuln.Fixed != "" {
				props["fixed_version"] = f.Vuln.Fixed
			}
			if f.Vuln.Vector != "" {
				props["cvss_vector"] = f.Vuln.Vector
			}
		}
		if f.Component != nil {
			props["component"] = f.Component.Name
			props["installed_version"] = f.Component.Version
		}
		if rule.Help.Text == "" {
			rule.Help = sarifText{msg}
		}
		rule.Properties["security-severity"] = securitySeverity(f)
		if old, ok := rules[id]; !ok || old.Default.Level != "error" {
			rules[id] = rule
		}
		uri := sarifURI(f.Path, r.Root)
		sum := sha256.Sum256([]byte(id + "\x00" + uri + "\x00" + msg))
		res := sarifResult{RuleID: id, Level: sarifLevel(f.Severity), Message: sarifText{msg},
			Locations:    []sarifLocation{{sarifPhysical{sarifArtifact{uri}}}},
			Fingerprints: map[string]string{"attackscoutFinding/v1": hex.EncodeToString(sum[:16])}}
		if fix != "" {
			res.Message.Text += "\n" + fix
		}
		if len(props) > 0 {
			res.Properties = props
		}
		results = append(results, res)
	}
	ids := make([]string, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	driver := sarifDriver{Name: "attackscout-agent", Version: version, InformationURI: ToolURL, Rules: []sarifRule{}}
	for _, id := range ids {
		driver.Rules = append(driver.Rules, rules[id])
	}
	log := sarifLog{Schema: "https://json.schemastore.org/sarif-2.1.0.json", Version: "2.1.0",
		Runs: []sarifRun{{Tool: sarifTool{driver}, Results: results}}}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}
