// Package scan runs the local, read-only checks. It never writes, deletes or
// fixes a file of the site. Network access is delegated to the vulns package
// and happens only when the caller passes an online matcher.
package scan

import (
	"context"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/attackscout/attackscout-agent/internal/eol"
	"github.com/attackscout/attackscout-agent/internal/i18n"
	"github.com/attackscout/attackscout-agent/internal/inventory"
	"github.com/attackscout/attackscout-agent/internal/vulns"
)

// Severity of a finding.
type Severity int

// Severities, from the least to the most severe.
const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var severityNames = []string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string { return severityNames[s] }

// MarshalText writes the severity name in JSON.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// ParseSeverity reads a severity name. "none" returns -1: nothing fails.
func ParseSeverity(s string) (Severity, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "none" || s == "" {
		return -1, nil
	}
	for i, n := range severityNames {
		if n == s {
			return Severity(i), nil
		}
	}
	return 0, fmt.Errorf("unknown severity %q (info, low, medium, high, critical, none)", s)
}

// Status of a check.
type Status string

// Statuses. A check that makes no sense on a system is not_applicable,
// never pass.
const (
	Pass          Status = "pass"
	Fail          Status = "fail"
	NotApplicable Status = "not_applicable"
	NotChecked    Status = "not_checked"
)

// Check is the outcome of one control.
type Check struct {
	ID     string   `json:"id"`
	Status Status   `json:"status"`
	Note   i18n.Msg `json:"note"`
}

// Finding is one result. Values of secrets are never stored here.
type Finding struct {
	ID        string               `json:"id"`
	Check     string               `json:"check"`
	Severity  Severity             `json:"severity"`
	Title     i18n.Msg             `json:"message"`
	Fix       i18n.Msg             `json:"fix"`
	Path      string               `json:"path,omitempty"`
	Component *inventory.Component `json:"component,omitempty"`
	Vuln      *vulns.Vuln          `json:"vulnerability,omitempty"`
	Certainty string               `json:"certainty,omitempty"`
}

// Item is a component and the state of its CVE check.
type Item struct {
	inventory.Component
	CVE   string       `json:"cve_status"` // checked, not_checked
	Vulns []vulns.Vuln `json:"vulnerabilities,omitempty"`
}

// Report is the full result.
type Report struct {
	Checks     []Check   `json:"checks"`
	Findings   []Finding `json:"findings"`
	Items      []Item    `json:"components"`
	EOLDate    string    `json:"eol_data_date"`
	CVEMode    string    `json:"cve_mode"` // offline, online, none
	Root       string    `json:"root,omitempty"`
	Nginx      string    `json:"nginx,omitempty"`
	Apache     string    `json:"apache,omitempty"`
	Generated  time.Time `json:"generated"`
	Unchecked  []string  `json:"cve_unchecked_ecosystems,omitempty"`
	ReadErrors []string  `json:"read_errors,omitempty"`
}

// Options selects what to scan. Empty fields are skipped.
type Options struct {
	Root     string   // web root
	Projects []string // other project directories
	Nginx    string   // nginx configuration directory
	Apache   string   // Apache configuration directory
	Certs    []string // PEM files
	Now      time.Time
	EOL      *eol.Table
	Exec     inventory.Exec
	// PHPHintDirs are directories whose names reveal PHP versions (/etc/php).
	PHPHintDirs []string
	// Matcher looks up CVEs; nil means not checked.
	Matcher vulns.Matcher
	// GOOS overrides runtime.GOOS (tests).
	GOOS string
}

// Run executes every check.
func Run(ctx context.Context, o Options) Report {
	if o.EOL == nil {
		o.EOL = eol.Default()
	}
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	if o.GOOS == "" {
		o.GOOS = runtime.GOOS
	}
	rep := Report{EOLDate: o.EOL.Updated, Root: o.Root, Nginx: o.Nginx, Apache: o.Apache, Generated: o.Now.UTC(), CVEMode: "none"}
	web := LoadWebConfig(o.Nginx, o.Apache, o.Root)
	inv := inventory.Collect(inventory.Options{Root: o.Root, Projects: o.Projects, Exec: o.Exec, PHPHintDirs: o.PHPHintDirs, ConfigText: web.Text()})
	rep.ReadErrors = inv.Errors

	add := func(id string, fs []Finding, empty Status, note i18n.Msg) {
		for i := range fs {
			fs[i].Check = id
		}
		rep.Findings = append(rep.Findings, fs...)
		st := empty
		for _, f := range fs {
			if f.Severity >= Low {
				st = Fail
			}
		}
		rep.Checks = append(rep.Checks, Check{ID: id, Status: st, Note: note})
	}

	// 1. End of life
	eolFs, known := CheckEOL(inv.Components, o.EOL, o.Now)
	if known == 0 {
		add("end-of-life", eolFs, NotChecked, i18n.M("note.eol.none"))
	} else {
		add("end-of-life", eolFs, Pass, i18n.M("note.eol.date", o.EOL.Updated))
	}

	// 2. CVE
	vfs, items, st, note, unchecked, mode := CheckVulns(ctx, inv.Components, o.Matcher)
	rep.Items, rep.Unchecked, rep.CVEMode = items, unchecked, mode
	add("vulnerabilities", vfs, st, note)

	// 3. Sensitive files, permissions, wp-config
	if o.Root == "" {
		for _, id := range []string{"sensitive-files", "permissions", "wp-config"} {
			add(id, nil, NotChecked, i18n.M("note.no-root"))
		}
	} else {
		add("sensitive-files", CheckSensitive(o.Root), Pass, i18n.Msg{})
		if o.GOOS == "windows" {
			add("permissions", nil, NotApplicable, i18n.M("note.perms.windows"))
		} else {
			add("permissions", CheckPerms(o.Root), Pass, i18n.Msg{})
		}
		if FindWPConfig(o.Root) == "" {
			add("wp-config", nil, NotApplicable, i18n.M("note.wpconfig.none"))
		} else {
			add("wp-config", CheckWPConfig(o.Root), Pass, i18n.Msg{})
		}
	}

	// 4. Web server
	wfs, wst, wnote := CheckWebConfig(web)
	add("web-server", wfs, wst, wnote)

	// 5. Certificates
	certs := dedupe(append(append([]string{}, o.Certs...), web.Certs...))
	if len(certs) == 0 {
		add("certificates", nil, NotChecked, i18n.M("note.cert.none"))
	} else {
		add("certificates", CheckCerts(certs, o.Now), Pass, i18n.Msg{})
	}

	Sort(rep.Findings)
	return rep
}

// Sort orders findings by severity (worst first), then by ID and path.
func Sort(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Severity != fs[j].Severity {
			return fs[i].Severity > fs[j].Severity
		}
		if fs[i].ID != fs[j].ID {
			return fs[i].ID < fs[j].ID
		}
		return fs[i].Path < fs[j].Path
	})
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
