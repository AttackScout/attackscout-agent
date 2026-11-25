package inventory

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var (
	rePHPv       = regexp.MustCompile(`PHP (\d+\.\d+\.\d+)`)
	rePHPHint    = regexp.MustCompile(`(?i)php-?(\d)\.?(\d)(?:-fpm|\b)`)
	reHintDir    = regexp.MustCompile(`^\d+\.\d+$`)
	reNodeV      = regexp.MustCompile(`^v?(\d+\.\d+\.\d+)`)
	reNodeFile   = regexp.MustCompile(`^v?(\d+(?:\.\d+){0,2})`)
	reDotnetRT   = regexp.MustCompile(`(?m)^Microsoft\.(?:NETCore|AspNetCore)\.App (\d+\.\d+\.\d+)`)
	reTargetFw   = regexp.MustCompile(`<TargetFrameworks?>([^<]+)</TargetFrameworks?>`)
	reNetMoniker = regexp.MustCompile(`^net(?:coreapp)?(\d+\.\d+)$`)
)

// Runtimes finds PHP, Node.js and .NET versions.
func Runtimes(o Options) []Component {
	var out []Component
	out = append(out, php(o)...)
	out = append(out, node(o)...)
	out = append(out, dotnet(o)...)
	return out
}

func php(o Options) []Component {
	if s, err := o.Exec("php", "-v"); err == nil {
		if m := rePHPv.FindStringSubmatch(s); m != nil {
			return []Component{{Kind: KindRuntime, Product: "php", Name: "PHP", Version: m[1], Source: "php -v", Exact: true}}
		}
	}
	hints := map[string]bool{}
	for _, m := range rePHPHint.FindAllStringSubmatch(o.ConfigText, -1) {
		hints[m[1]+"."+m[2]] = true
	}
	for _, d := range o.PHPHintDirs {
		entries, _ := os.ReadDir(d)
		for _, e := range entries {
			if e.IsDir() && reHintDir.MatchString(e.Name()) {
				hints[e.Name()] = true
			}
		}
	}
	var vs []string
	for v := range hints {
		vs = append(vs, v)
	}
	sort.Strings(vs)
	var out []Component
	for _, v := range vs {
		out = append(out, Component{Kind: KindRuntime, Product: "php", Name: "PHP", Version: v, Source: "configuration hint"})
	}
	return out
}

func node(o Options) []Component {
	if s, err := o.Exec("node", "--version"); err == nil {
		if m := reNodeV.FindStringSubmatch(strings.TrimSpace(s)); m != nil {
			return []Component{{Kind: KindRuntime, Product: "nodejs", Name: "Node.js", Version: m[1], Source: "node --version", Exact: true}}
		}
	}
	var out []Component
	for _, d := range dedupe(append([]string{o.Root}, o.Projects...)) {
		for _, f := range []string{".nvmrc", ".node-version"} {
			p := filepath.Join(d, f)
			data, err := readSmall(p)
			if err != nil {
				continue
			}
			if m := reNodeFile.FindStringSubmatch(strings.TrimSpace(string(data))); m != nil {
				out = append(out, Component{Kind: KindRuntime, Product: "nodejs", Name: "Node.js", Version: m[1], Source: p})
			}
		}
	}
	return out
}

func dotnet(o Options) []Component {
	if s, err := o.Exec("dotnet", "--list-runtimes"); err == nil {
		var out []Component
		seen := map[string]bool{}
		for _, m := range reDotnetRT.FindAllStringSubmatch(s, -1) {
			if !seen[m[1]] {
				seen[m[1]] = true
				out = append(out, Component{Kind: KindRuntime, Product: "dotnet", Name: ".NET", Version: m[1], Source: "dotnet --list-runtimes", Exact: true})
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	var out []Component
	read := map[string]bool{}
	for _, d := range dedupe(append([]string{o.Root}, o.Projects...)) {
		files, _ := filepath.Glob(filepath.Join(d, "*.csproj"))
		more, _ := filepath.Glob(filepath.Join(d, "*", "*.csproj"))
		for _, f := range append(files, more...) {
			if abs, err := filepath.Abs(f); err == nil {
				if read[abs] {
					continue
				}
				read[abs] = true
			}
			data, err := readSmall(f)
			if err != nil {
				continue
			}
			for _, m := range reTargetFw.FindAllStringSubmatch(string(data), -1) {
				for _, t := range strings.Split(m[1], ";") {
					if mm := reNetMoniker.FindStringSubmatch(strings.TrimSpace(t)); mm != nil {
						out = append(out, Component{Kind: KindRuntime, Product: "dotnet", Name: ".NET", Version: mm[1], Source: f})
					}
				}
			}
		}
	}
	return out
}
