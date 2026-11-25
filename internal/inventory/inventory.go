// Package inventory lists what runs on the server: runtimes, CMS cores and
// their plugins, modules and themes, front-end frameworks, Terraform and its
// providers, and the dependencies found in lockfiles. Lockfiles are read by
// the osv-scalibr extractors (Apache-2.0). Nothing is sent over the network.
package inventory

import (
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/google/osv-scalibr/extractor"
)

// Kinds of components.
const (
	KindRuntime           = "runtime"
	KindCMS               = "cms"
	KindCMSPlugin         = "cms-plugin"
	KindCMSTheme          = "cms-theme"
	KindCMSModule         = "cms-module"
	KindCMSExtension      = "cms-extension"
	KindFramework         = "framework"
	KindDependency        = "dependency"
	KindTerraform         = "terraform"
	KindTerraformProvider = "terraform-provider"
)

// OSV ecosystems, as named in the OSV database.
const (
	EcoNPM       = "npm"
	EcoPackagist = "Packagist"
	EcoPyPI      = "PyPI"
	EcoNuGet     = "NuGet"
	EcoGo        = "Go"
)

// Ecosystems lists the ecosystems that "db update" downloads.
var Ecosystems = []string{EcoNPM, EcoPackagist, EcoPyPI, EcoNuGet, EcoGo}

var purlTypes = map[string]string{EcoNPM: "npm", EcoPackagist: "composer", EcoPyPI: "pypi", EcoNuGet: "nuget", EcoGo: "golang"}

// EcosystemOfPURL maps a purl type to its OSV ecosystem ("" if not tracked).
func EcosystemOfPURL(t string) string {
	for eco, p := range purlTypes {
		if p == t {
			return eco
		}
	}
	return ""
}

// PURLType maps an OSV ecosystem to its purl type.
func PURLType(eco string) string { return purlTypes[eco] }

// Component is one piece of software with its version.
type Component struct {
	Kind      string `json:"kind"`
	Product   string `json:"product,omitempty"` // key in the end-of-life table
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem,omitempty"` // OSV ecosystem, empty when OSV has none
	Package   string `json:"package,omitempty"`   // OSV package name
	Source    string `json:"source"`
	// Exact: the version was read as is (lockfile, version header, command);
	// otherwise it was deduced (constraint, configuration hint).
	Exact bool `json:"exact"`
	// Raw is the osv-scalibr package for lockfile entries: its metadata marks
	// local packages, which are never sent to osv.dev.
	Raw *extractor.Package `json:"-"`
}

// Certainty is "high" for an exact version, "medium" for a deduced one.
func (c Component) Certainty() string {
	if c.Exact {
		return "high"
	}
	return "medium"
}

// Pkg returns the osv-scalibr package used for vulnerability matching.
func (c Component) Pkg() *extractor.Package {
	if c.Raw != nil {
		return c.Raw
	}
	return &extractor.Package{Name: c.Package, Version: c.Version, PURLType: PURLType(c.Ecosystem)}
}

// Exec runs a local command and returns its output. It never touches the network.
type Exec func(name string, args ...string) (string, error)

// LocalExec runs a command found in PATH, if any.
func LocalExec(name string, args ...string) (string, error) {
	p, err := exec.LookPath(name)
	if err != nil {
		return "", err
	}
	out, err := exec.Command(p, args...).CombinedOutput() //nolint:gosec // fixed commands only
	return string(out), err
}

// Options selects where to look.
type Options struct {
	Root     string   // web root
	Projects []string // other project directories (lockfiles, Terraform)
	Exec     Exec
	// PHPHintDirs are directories whose sub-directories name PHP versions (/etc/php).
	PHPHintDirs []string
	// ConfigText is the web server configuration, for PHP hints.
	ConfigText string
}

// Result is the inventory and the errors met while reading lockfiles.
type Result struct {
	Components []Component
	Errors     []string
}

// Collect builds the inventory.
func Collect(o Options) Result {
	var r Result
	if o.Exec == nil {
		o.Exec = func(string, ...string) (string, error) { return "", os.ErrNotExist }
	}
	r.Components = append(r.Components, Runtimes(o)...)
	dirs := dedupe(append([]string{o.Root}, o.Projects...))
	for _, d := range dirs {
		if d == o.Root {
			r.Components = append(r.Components, CMS(d)...)
		}
		deps, err := Lockfiles(d)
		if err != nil {
			r.Errors = append(r.Errors, err.Error())
		}
		fw := Frameworks(d, deps)
		r.Components = append(r.Components, withoutFrameworks(deps, fw)...)
		r.Components = append(r.Components, fw...)
		r.Components = append(r.Components, Terraform(d)...)
	}
	r.Components = append(r.Components, TerraformBinaries(o.Exec)...)
	r.Components = uniq(r.Components)
	return r
}

// withoutFrameworks drops the lockfile entries promoted to frameworks.
func withoutFrameworks(deps, fw []Component) []Component {
	var out []Component
	for _, d := range deps {
		keep := true
		for _, f := range fw {
			if f.Package == d.Package && f.Version == d.Version && f.Source == d.Source {
				keep = false
			}
		}
		if keep {
			out = append(out, d)
		}
	}
	return out
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

func uniq(cs []Component) []Component {
	seen := map[string]bool{}
	var out []Component
	for _, c := range cs {
		k := strings.Join([]string{c.Kind, c.Name, c.Version, c.Ecosystem, c.Source}, "\x00")
		if !seen[k] {
			seen[k] = true
			out = append(out, c)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return kindRank(out[i].Kind) < kindRank(out[j].Kind)
		}
		return out[i].Name < out[j].Name
	})
	return out
}

var kindOrder = []string{KindRuntime, KindCMS, KindCMSPlugin, KindCMSModule, KindCMSExtension, KindCMSTheme, KindFramework, KindTerraform, KindTerraformProvider, KindDependency}

func kindRank(k string) int {
	for i, o := range kindOrder {
		if o == k {
			return i
		}
	}
	return len(kindOrder)
}

// readSmall reads a regular file of at most 1 MB.
func readSmall(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > 1<<20 {
		return nil, os.ErrInvalid
	}
	return os.ReadFile(path)
}
