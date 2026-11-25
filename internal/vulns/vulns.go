// Package vulns matches the inventory against the OSV database with the
// osv-scalibr library (Apache-2.0).
//
// This is the only package of attackscout-agent that can open a network
// connection, and only on two explicit paths: Update ("db update") and
// Online ("--online"). The default path, Offline, reads local archives and
// gives the library an HTTP client that refuses every request.
package vulns

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/enricher/vulnmatch/osvdev"
	"github.com/google/osv-scalibr/enricher/vulnmatch/osvlocal"
	"github.com/google/osv-scalibr/extractor"
	scalibrinv "github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin/config"
	"github.com/google/osv-scalibr/semantic"
	osvpb "github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/grpc"
	osvdevclient "osv.dev/bindings/go/osvdev"

	"github.com/attackscout/attackscout-agent/internal/inventory"
)

// Default remote locations, used only by Update and Online.
const (
	DefaultArchiveHost = "https://osv-vulnerabilities.storage.googleapis.com"
	DefaultAPI         = osvdevclient.DefaultBaseURL
	userAgent          = "attackscout-agent"
)

// Vuln is one vulnerability affecting a component.
type Vuln struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases,omitempty"`
	Summary  string   `json:"summary,omitempty"`
	Score    float64  `json:"cvss_score,omitempty"`
	Vector   string   `json:"cvss_vector,omitempty"`
	Severity string   `json:"severity"` // low, medium, high, critical
	Fixed    string   `json:"fixed,omitempty"`
}

// CVE returns the first CVE identifier, or the OSV identifier.
func (v Vuln) CVE() string {
	if strings.HasPrefix(v.ID, "CVE-") {
		return v.ID
	}
	for _, a := range v.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	return v.ID
}

// Result holds the matches by component index and the ecosystems checked.
type Result struct {
	Vulns   map[int][]Vuln
	Checked map[string]bool   // ecosystem → checked
	Reasons map[string]string // ecosystem → why it was not checked
	DBDates map[string]time.Time
	Mode    string // "offline" or "online"
}

func newResult(mode string) Result {
	return Result{Vulns: map[int][]Vuln{}, Checked: map[string]bool{}, Reasons: map[string]string{}, DBDates: map[string]time.Time{}, Mode: mode}
}

// Matcher finds vulnerabilities for components.
type Matcher interface {
	Match(ctx context.Context, comps []inventory.Component) Result
}

// ErrNetworkDisabled is returned by the HTTP client of the offline path.
var ErrNetworkDisabled = errors.New("network access is disabled in offline mode")

// refusals counts the requests refused on the offline path (tests).
var refusals atomic.Int64

// Refusals returns how many HTTP requests the offline path refused.
func Refusals() int64 { return refusals.Load() }

type refuse struct{}

func (refuse) RoundTrip(*http.Request) (*http.Response, error) {
	refusals.Add(1)
	return nil, ErrNetworkDisabled
}

type factories struct{ c *http.Client }

func (f factories) HTTPClient() *http.Client { return f.c }
func (f factories) GoogleHTTPClient(context.Context, ...string) (*http.Client, error) {
	return nil, ErrNetworkDisabled
}

// GRPCClientConn is never used by the enrichers of this tool.
func (f factories) GRPCClientConn(string, ...grpc.DialOption) (grpc.ClientConnInterface, error) {
	return nil, ErrNetworkDisabled
}

func localConfig(dir, remote string, download bool, c *http.Client) *config.PluginConfig {
	return &config.PluginConfig{
		ClientFactories: factories{c},
		ProtoConfig: &cpb.PluginConfig{UserAgent: userAgent, PluginSpecific: []*cpb.PluginSpecificConfig{{
			Config: &cpb.PluginSpecificConfig_Osvlocal{Osvlocal: &cpb.OSVLocalConfig{Download: download, LocalPath: dir, RemoteHost: remote}},
		}}},
	}
}

// ArchivePath is where the library keeps the archive of an ecosystem.
func ArchivePath(dir, eco string) string {
	return filepath.Join(dir, "osv-scalibr", eco, "all.zip")
}

// NewHTTPClient returns the client of the two network paths.
func NewHTTPClient() *http.Client { return &http.Client{Timeout: 10 * time.Minute} }

// DefaultDir is the user cache directory for the OSV archives.
func DefaultDir() string {
	d, err := os.UserCacheDir()
	if err != nil {
		d = os.TempDir()
	}
	return filepath.Join(d, "attackscout-agent")
}

// Offline matches against archives downloaded earlier by Update. It never
// downloads anything.
type Offline struct{ Dir string }

// Match implements Matcher.
func (o Offline) Match(ctx context.Context, comps []inventory.Component) Result {
	r := newResult("offline")
	for eco, idx := range byEcosystem(comps) {
		st, err := os.Stat(ArchivePath(o.Dir, eco))
		if err != nil {
			r.Reasons[eco] = "no local database"
			continue
		}
		r.DBDates[eco] = st.ModTime()
		e, err := osvlocal.New(localConfig(o.Dir, DefaultArchiveHost, false, &http.Client{Transport: refuse{}}))
		if err != nil {
			r.Reasons[eco] = err.Error()
			continue
		}
		run(ctx, e, comps, idx, &r, eco)
	}
	return r
}

// Online sends package names, versions and ecosystems to the osv.dev API.
// Nothing else leaves the machine: no path, host or domain name.
type Online struct {
	BaseURL string
	Client  *http.Client
}

// Match implements Matcher.
func (o Online) Match(ctx context.Context, comps []inventory.Component) Result {
	r := newResult("online")
	groups := byEcosystem(comps)
	if len(groups) == 0 {
		return r
	}
	c := &osvdevclient.OSVClient{HTTPClient: o.Client, Config: osvdevclient.DefaultConfig(), BaseHostURL: o.BaseURL}
	c.Config.UserAgent = userAgent
	e := osvdev.NewWithClient(c, 2*time.Minute)
	var all []int
	for _, idx := range groups {
		all = append(all, idx...)
	}
	sort.Ints(all)
	run(ctx, e, comps, all, &r, "")
	if len(r.Reasons) == 0 {
		for eco := range groups {
			r.Checked[eco] = true
		}
	} else {
		for eco := range groups {
			r.Reasons[eco] = r.Reasons[""]
		}
		delete(r.Reasons, "")
	}
	return r
}

func byEcosystem(comps []inventory.Component) map[string][]int {
	out := map[string][]int{}
	for i, c := range comps {
		if c.Ecosystem != "" && c.Package != "" && c.Version != "" {
			out[c.Ecosystem] = append(out[c.Ecosystem], i)
		}
	}
	return out
}

func run(ctx context.Context, e enricher.Enricher, comps []inventory.Component, idx []int, r *Result, eco string) {
	inv := &scalibrinv.Inventory{}
	where := map[*extractor.Package][]int{}
	for _, i := range idx {
		p := comps[i].Pkg()
		if _, ok := where[p]; !ok {
			inv.Packages = append(inv.Packages, p)
		}
		where[p] = append(where[p], i)
	}
	if err := e.Enrich(ctx, nil, inv); err != nil {
		r.Reasons[eco] = err.Error()
		return
	}
	if eco != "" {
		r.Checked[eco] = true
	}
	for _, pv := range inv.PackageVulns {
		for _, i := range where[pv.Package] {
			r.Vulns[i] = append(r.Vulns[i], Convert(pv.Vulnerability, comps[i]))
		}
	}
	for i := range r.Vulns {
		sort.Slice(r.Vulns[i], func(a, b int) bool { return r.Vulns[i][a].ID < r.Vulns[i][b].ID })
	}
}

// Update downloads the OSV archive of each ecosystem into dir, through the
// osv-scalibr download mechanism. It is called by "db update" only.
func Update(ctx context.Context, dir, remote string, c *http.Client, ecosystems []string) map[string]error {
	out := map[string]error{}
	for _, eco := range ecosystems {
		e, err := osvlocal.New(localConfig(dir, remote, true, c))
		if err == nil {
			inv := &scalibrinv.Inventory{Packages: []*extractor.Package{{Name: "attackscout-agent-db-update", Version: "0.0.0", PURLType: inventory.PURLType(eco)}}}
			err = e.Enrich(ctx, nil, inv)
		}
		if err == nil {
			if _, serr := os.Stat(ArchivePath(dir, eco)); serr != nil {
				err = serr
			}
		}
		out[eco] = err
	}
	return out
}

// Convert turns an OSV record into a Vuln for component c.
func Convert(v *osvpb.Vulnerability, c inventory.Component) Vuln {
	out := Vuln{ID: v.GetId(), Aliases: v.GetAliases(), Summary: v.GetSummary()}
	for _, s := range v.GetSeverity() {
		if s.GetType() == osvpb.Severity_CVSS_V3 {
			if score, ok := CVSS3(s.GetScore()); ok {
				out.Score, out.Vector = score, s.GetScore()
			}
		}
	}
	if out.Vector == "" {
		for _, a := range v.GetAffected() {
			for _, s := range a.GetSeverity() {
				if s.GetType() == osvpb.Severity_CVSS_V3 {
					if score, ok := CVSS3(s.GetScore()); ok {
						out.Score, out.Vector = score, s.GetScore()
					}
				}
			}
		}
	}
	switch {
	case out.Vector != "":
		out.Severity = ScoreSeverity(out.Score)
	case strings.HasPrefix(out.ID, "MAL-"):
		out.Severity = "critical"
	default:
		out.Severity = databaseSeverity(v)
	}
	out.Fixed = smallestFix(v, c)
	return out
}

func databaseSeverity(v *osvpb.Vulnerability) string {
	if ds := v.GetDatabaseSpecific(); ds != nil {
		if f, ok := ds.GetFields()["severity"]; ok {
			switch strings.ToLower(f.GetStringValue()) {
			case "critical":
				return "critical"
			case "high":
				return "high"
			case "low":
				return "low"
			}
		}
	}
	return "medium"
}

// smallestFix returns the smallest "fixed" version above the installed one.
func smallestFix(v *osvpb.Vulnerability, c inventory.Component) string {
	installed, err := semantic.Parse(c.Version, c.Ecosystem)
	best := ""
	var bestV semantic.Version
	for _, a := range v.GetAffected() {
		if a.GetPackage().GetName() != c.Package && !strings.EqualFold(a.GetPackage().GetName(), c.Package) {
			continue
		}
		for _, rg := range a.GetRanges() {
			for _, ev := range rg.GetEvents() {
				f := ev.GetFixed()
				if f == "" {
					continue
				}
				fv, ferr := semantic.Parse(f, c.Ecosystem)
				if ferr != nil {
					if best == "" {
						best = f
					}
					continue
				}
				if err == nil {
					if cmp, cerr := installed.CompareStr(f); cerr == nil && cmp >= 0 {
						continue // already at or above this fix
					}
				}
				if bestV == nil {
					best, bestV = f, fv
					continue
				}
				if cmp, cerr := bestV.CompareStr(f); cerr == nil && cmp > 0 {
					best, bestV = f, fv
				}
			}
		}
	}
	return best
}
