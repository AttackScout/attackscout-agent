package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/csproj"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/packagesconfig"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/packageslockjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gomod"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/pomxml"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagelockjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/pnpmlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/yarnlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/php/composerlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/poetrylock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
	"github.com/google/osv-scalibr/extractor/filesystem/language/ruby/gemfilelock"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"
	scalibrlog "github.com/google/osv-scalibr/log"
)

// The extractors used: all of them work offline.
var extractorFactories = []func(*cpb.PluginConfig) (filesystem.Extractor, error){
	packagelockjson.New, yarnlock.New, pnpmlock.New,
	composerlock.New,
	requirements.New, poetrylock.New,
	gemfilelock.New,
	gomod.New,
	pomxml.New,
	packageslockjson.New, csproj.New, packagesconfig.New,
}

// skipDirs: installed copies are not lockfiles; vendor and node_modules are
// read through their lockfiles.
var skipDirs = regexp.MustCompile(`(^|[/\\])(node_modules|vendor|\.git|\.terraform)$`)

func init() { scalibrlog.SetLogger(quiet{}) }

// quiet silences osv-scalibr logs: the report is the only output.
type quiet struct{}

func (quiet) Errorf(string, ...any) {}
func (quiet) Error(...any)          {}
func (quiet) Warnf(string, ...any)  {}
func (quiet) Warn(...any)           {}
func (quiet) Infof(string, ...any)  {}
func (quiet) Info(...any)           {}
func (quiet) Debugf(string, ...any) {}
func (quiet) Debug(...any)          {}

// maxLockDepth limits how deep lockfiles are searched under a directory.
const maxLockDepth = 8

// Lockfiles reads npm, Yarn (v1 and Berry), pnpm, Composer, pip
// requirements, Poetry, Bundler, Go modules, Maven and NuGet files under dir with the osv-scalibr extractors.
// Only the file walk is done here; parsing is left to the library.
func Lockfiles(dir string) ([]Component, error) {
	var exts []filesystem.Extractor
	for _, f := range extractorFactories {
		e, err := f(&cpb.PluginConfig{})
		if err != nil {
			return nil, err
		}
		exts = append(exts, e)
	}
	if _, err := os.Stat(dir); err != nil {
		return nil, err
	}
	sfs := scalibrfs.DirFS(dir)
	var out []Component
	var errs []error
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if p != dir && (skipDirs.MatchString(d.Name()) || strings.Count(rel, "/") >= maxLockDepth) {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<20 {
			return nil
		}
		if d.Name() == "go.sum" {
			if _, err := os.Stat(filepath.Join(filepath.Dir(p), "go.mod")); err != nil {
				out = append(out, GoSum(p)...)
			}
			return nil
		}
		for _, e := range exts {
			if !e.FileRequired(simplefileapi.New(rel, info)) {
				continue
			}
			pkgs, err := extract(e, sfs, dir, rel, p, info)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", p, err))
				continue
			}
			for _, pkg := range pkgs {
				eco := EcosystemOfPURL(pkg.PURLType)
				if eco == "" || pkg.Version == "" || strings.Contains(pkg.Version, "${") {
					continue
				}
				out = append(out, Component{Kind: KindDependency, Name: pkg.Name, Version: pkg.Version,
					Ecosystem: eco, Package: pkg.Name, Source: p, Exact: exact(pkg, p), Raw: pkg})
			}
		}
		return nil
	})
	return out, errors.Join(errs...)
}

func extract(e filesystem.Extractor, sfs scalibrfs.FS, root, rel, full string, info fs.FileInfo) ([]*extractor.Package, error) {
	f, err := os.Open(full)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	inv, err := e.Extract(context.Background(), &filesystem.ScanInput{FS: sfs, Path: rel, Root: root, Info: info, Reader: f})
	return inv.Packages, err
}

// exact tells whether the version is pinned: lockfiles and packages.config
// are; a requirement such as "requests>=2.20" or a .csproj reference is a
// constraint whose smallest version is used.
func exact(p *extractor.Package, src string) bool {
	if m, ok := p.Metadata.(*requirements.Metadata); ok {
		return m.VersionComparator == "==" || m.VersionComparator == "==="
	}
	return !strings.EqualFold(filepath.Ext(src), ".csproj")
}

var frameworks = []struct{ pkg, product, label string }{
	{"react", "react", "React"},
	{"next", "nextjs", "Next.js"},
}

// Frameworks reports React and Next.js, from the lockfile packages or from
// node_modules/<name>/package.json.
func Frameworks(dir string, deps []Component) []Component {
	var out []Component
	for _, f := range frameworks {
		found := false
		for _, d := range deps {
			if d.Ecosystem == EcoNPM && d.Name == f.pkg {
				c := d
				c.Kind, c.Product, c.Name = KindFramework, f.product, f.label
				out = append(out, c)
				found = true
			}
		}
		if found {
			continue
		}
		p := filepath.Join(dir, "node_modules", f.pkg, "package.json")
		data, err := readSmall(p)
		if err != nil {
			continue
		}
		var pj struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		if json.Unmarshal(data, &pj) == nil && pj.Name == f.pkg && pj.Version != "" {
			out = append(out, Component{Kind: KindFramework, Product: f.product, Name: f.label, Version: pj.Version,
				Ecosystem: EcoNPM, Package: f.pkg, Source: p, Exact: true})
		}
	}
	return out
}

// GoSum reads a go.sum without its go.mod: the highest version of each
// module is kept. The versions are exact but may include unused ones.
func GoSum(path string) []Component {
	data, err := readSmall(path)
	if err != nil {
		return nil
	}
	best := map[string]string{}
	var order []string
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) != 3 || strings.HasSuffix(f[1], "/go.mod") {
			continue
		}
		v := strings.TrimPrefix(f[1], "v")
		if old, ok := best[f[0]]; !ok {
			order = append(order, f[0])
			best[f[0]] = v
		} else if semverLess(old, v) {
			best[f[0]] = v
		}
	}
	var out []Component
	for _, m := range order {
		out = append(out, Component{Kind: KindDependency, Name: m, Version: best[m], Ecosystem: EcoGo, Package: m, Source: path, Exact: true})
	}
	return out
}

// semverLess compares the numeric parts of two versions.
func semverLess(a, b string) bool {
	pa := strings.FieldsFunc(a, func(r rune) bool { return r == '.' || r == '-' || r == '+' })
	pb := strings.FieldsFunc(b, func(r rune) bool { return r == '.' || r == '-' || r == '+' })
	for i := 0; i < len(pa) && i < len(pb) && i < 3; i++ {
		if pa[i] != pb[i] {
			return numLess(pa[i], pb[i])
		}
	}
	return len(pa) < len(pb) && len(pa) < 3
}
