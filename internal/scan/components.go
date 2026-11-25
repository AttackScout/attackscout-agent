package scan

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/attackscout/attackscout-agent/internal/eol"
	"github.com/attackscout/attackscout-agent/internal/i18n"
	"github.com/attackscout/attackscout-agent/internal/inventory"
	"github.com/attackscout/attackscout-agent/internal/vulns"
)

// soonDays: an end of life closer than this is reported as a warning.
const soonDays = 90

// CheckEOL looks up the end of life of runtimes, CMS and frameworks. It
// returns the findings and how many components were looked up.
func CheckEOL(comps []inventory.Component, t *eol.Table, now time.Time) ([]Finding, int) {
	var out []Finding
	n := 0
	for i := range comps {
		c := comps[i]
		if c.Product == "" || c.Version == "" {
			continue
		}
		n++
		st := t.Lookup(c.Product, c.Version, now)
		cp := &comps[i]
		base := Finding{Path: c.Source, Component: cp, Certainty: c.Certainty()}
		f := base
		switch {
		case !st.Known:
			f.ID, f.Severity, f.Title = c.Product+"-version", Info, i18n.M("eol.unknown", c.Name, c.Version)
			out = append(out, f)
			continue
		case st.EOL && st.EOLDate != nil:
			f.ID, f.Severity = c.Product+"-eol", High
			f.Title = i18n.M("eol.ended.date", c.Name, c.Version, st.Cycle, st.EOLDate.Format("2006-01-02"))
			f.Fix = i18n.M("eol.fix", c.Name, st.Link)
			out = append(out, f)
			continue
		case st.EOL:
			f.ID, f.Severity = c.Product+"-eol", High
			f.Title = i18n.M("eol.ended", c.Name, c.Version, st.Cycle)
			f.Fix = i18n.M("eol.fix", c.Name, st.Link)
			out = append(out, f)
			continue
		}
		added := false
		if st.EOLDate != nil && st.DaysLeft < soonDays {
			f.ID, f.Severity = c.Product+"-eol-soon", Medium
			f.Title = i18n.M("eol.soon", c.Name, c.Version, st.EOLDate.Format("2006-01-02"), st.DaysLeft)
			f.Fix = i18n.M("eol.soon.fix", c.Name, st.Link)
			out = append(out, f)
			added = true
		}
		if st.Behind && c.Exact {
			g := base
			g.ID, g.Severity = c.Product+"-patch-behind", Low
			g.Title = i18n.M("eol.behind", c.Name, c.Version, st.Latest, st.Cycle, t.Updated)
			g.Fix = i18n.M("eol.behind.fix", c.Name, st.Cycle)
			out = append(out, g)
			added = true
		}
		if !added {
			f.ID, f.Severity, f.Title = c.Product+"-version", Info, i18n.M("eol.supported", c.Name, c.Version, st.Cycle)
			out = append(out, f)
		}
	}
	return out, n
}

func toSeverity(s string) Severity {
	switch s {
	case "critical":
		return Critical
	case "high":
		return High
	case "low":
		return Low
	}
	return Medium
}

// CheckVulns looks up CVEs for every component with an OSV ecosystem.
func CheckVulns(ctx context.Context, comps []inventory.Component, m vulns.Matcher) (fs []Finding, items []Item, st Status, note i18n.Msg, unchecked []string, mode string) {
	items = make([]Item, len(comps))
	for i, c := range comps {
		items[i] = Item{Component: c, CVE: "not_checked"}
	}
	if len(comps) == 0 {
		return nil, items, NotApplicable, i18n.M("note.cve.no-components"), nil, "none"
	}
	mode = "none"
	var r vulns.Result
	if m != nil {
		r = m.Match(ctx, comps)
		mode = r.Mode
	}
	missing := map[string]bool{}
	noEco := 0
	for i, c := range comps {
		switch {
		case c.Ecosystem == "":
			noEco++
		case r.Checked[c.Ecosystem]:
			items[i].CVE = "checked"
			items[i].Vulns = r.Vulns[i]
		default:
			missing[c.Ecosystem] = true
		}
	}
	for i, c := range comps {
		for _, v := range r.Vulns[i] {
			v := v
			cp := &items[i].Component
			f := Finding{ID: "vulnerable-component", Severity: toSeverity(v.Severity), Path: c.Source,
				Component: cp, Vuln: &v, Certainty: c.Certainty()}
			score := "?"
			if v.Vector != "" {
				score = strconv.FormatFloat(v.Score, 'f', 1, 64)
			}
			f.Title = i18n.M("cve.title", c.Name, c.Version, v.CVE(), score, v.Summary)
			if v.Fixed != "" {
				f.Fix = i18n.M("cve.fix", c.Name, v.Fixed)
			} else {
				f.Fix = i18n.M("cve.nofix", c.Name)
			}
			fs = append(fs, f)
		}
	}
	for e := range missing {
		unchecked = append(unchecked, e)
	}
	sort.Strings(unchecked)
	switch {
	case len(fs) > 0 && len(unchecked) > 0:
		st, note = Fail, i18n.M("note.cve.partial", strings.Join(unchecked, ", "))
	case len(fs) > 0:
		st = Fail
	case m == nil:
		st, note = NotChecked, i18n.M("note.cve.run-db-update")
	case len(unchecked) > 0:
		st, note = NotChecked, i18n.M("note.cve.partial", strings.Join(unchecked, ", "))
	case noEco == len(comps):
		st, note = NotChecked, i18n.M("note.cve.no-ecosystem", noEco)
	default:
		st = Pass
	}
	if note.IsZero() && noEco > 0 {
		note = i18n.M("note.cve.no-ecosystem", noEco)
	}
	if note.IsZero() && mode == "offline" {
		note = i18n.M("note.cve.offline", oldest(r.DBDates))
	}
	if note.IsZero() && mode == "online" {
		note = i18n.M("note.cve.online")
	}
	return fs, items, st, note, unchecked, mode
}

func oldest(m map[string]time.Time) string {
	var t time.Time
	for _, d := range m {
		if t.IsZero() || d.Before(t) {
			t = d
		}
	}
	if t.IsZero() {
		return "?"
	}
	return t.UTC().Format("2006-01-02")
}
