package inventory

import (
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Terraform inventory only: provider and core versions, never an analysis
// of the configuration itself.

var (
	reLockProvider = regexp.MustCompile(`(?s)provider\s+"([^"]+)"\s*\{[^}]*?\bversion\s*=\s*"([^"]+)"`)
	reReqVersion   = regexp.MustCompile(`required_version\s*=\s*"([^"]+)"`)
	reProvBlock    = regexp.MustCompile(`([A-Za-z][\w-]*)\s*=\s*\{([^{}]*)\}`)
	reProvString   = regexp.MustCompile(`(?m)^\s*([A-Za-z][\w-]*)\s*=\s*"([^"]+)"`)
	reAttrSource   = regexp.MustCompile(`source\s*=\s*"([^"]+)"`)
	reAttrVersion  = regexp.MustCompile(`version\s*=\s*"([^"]+)"`)
	reTFBinary     = regexp.MustCompile(`(?m)^(Terraform|OpenTofu) v(\d+\.\d+\.\d+)`)
	reNumVersion   = regexp.MustCompile(`^v?(\d+(?:\.\d+){0,2})$`)
	reConstraint   = regexp.MustCompile(`^(>=|~>|=|>|<=|<|!=)?\s*v?(\d+(?:\.\d+){0,2})`)
)

// providerModule maps "hashicorp/aws" to the Go module of the provider.
func providerModule(source string) (label, module string) {
	parts := strings.Split(strings.Trim(source, "/"), "/")
	if len(parts) < 2 {
		parts = []string{"hashicorp", parts[0]}
	}
	ns, name := strings.ToLower(parts[len(parts)-2]), strings.ToLower(parts[len(parts)-1])
	return ns + "/" + name, "github.com/" + ns + "/terraform-provider-" + name
}

// pad3 turns "5.1" into "5.1.0".
func pad3(v string) string {
	for strings.Count(v, ".") < 2 {
		v += ".0"
	}
	return v
}

func numLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < 3; i++ {
		x, _ := strconv.Atoi(at(pa, i))
		y, _ := strconv.Atoi(at(pb, i))
		if x != y {
			return x < y
		}
	}
	return false
}

func at(s []string, i int) string {
	if i < len(s) {
		return s[i]
	}
	return "0"
}

// MinVersion returns the smallest version a Terraform constraint allows,
// such as "5.0.0" for "~> 5.0" or ">= 5.0, < 6.0". ok is false without a
// lower bound.
func MinVersion(constraint string) (string, bool) {
	best := ""
	for _, part := range strings.Split(constraint, ",") {
		m := reConstraint.FindStringSubmatch(strings.TrimSpace(part))
		if m == nil {
			continue
		}
		switch m[1] {
		case "", "=", ">=", "~>", ">":
			v := pad3(m[2])
			if best == "" || numLess(best, v) {
				best = v
			}
		}
	}
	return best, best != ""
}

// tfFiles lists .tf files up to three levels below dir.
func tfFiles(dir string) []string {
	var out []string
	pattern := filepath.Join(dir, "*.tf")
	for i := 0; i < 4; i++ {
		m, _ := filepath.Glob(pattern)
		for _, f := range m {
			if !strings.Contains(filepath.ToSlash(f), "/.terraform/") {
				out = append(out, f)
			}
		}
		pattern = filepath.Join(filepath.Dir(pattern), "*", "*.tf")
	}
	return out
}

// Terraform lists Terraform and OpenTofu versions and providers in dir.
func Terraform(dir string) []Component {
	var out []Component
	locked := map[string]bool{}
	lock := filepath.Join(dir, ".terraform.lock.hcl")
	if data, err := readSmall(lock); err == nil {
		for _, m := range reLockProvider.FindAllStringSubmatch(string(data), -1) {
			label, module := providerModule(m[1])
			locked[label] = true
			out = append(out, Component{Kind: KindTerraformProvider, Name: label, Version: strings.TrimPrefix(m[2], "v"),
				Ecosystem: EcoGo, Package: module, Source: lock, Exact: true})
		}
	}
	for _, f := range tfFiles(dir) {
		data, err := readSmall(f)
		if err != nil {
			continue
		}
		text := string(data)
		for _, block := range blocks(text, "required_providers") {
			type entry struct{ name, source, constraint string }
			var entries []entry
			for _, m := range reProvBlock.FindAllStringSubmatch(block, -1) {
				e := entry{name: m[1], source: m[1]}
				if s := reAttrSource.FindStringSubmatch(m[2]); s != nil {
					e.source = s[1]
				}
				if v := reAttrVersion.FindStringSubmatch(m[2]); v != nil {
					e.constraint = v[1]
				}
				entries = append(entries, e)
			}
			for _, m := range reProvString.FindAllStringSubmatch(reProvBlock.ReplaceAllString(block, ""), -1) {
				entries = append(entries, entry{name: m[1], source: m[1], constraint: m[2]})
			}
			for _, e := range entries {
				label, module := providerModule(e.source)
				v, ok := MinVersion(e.constraint)
				if locked[label] || !ok {
					continue
				}
				out = append(out, Component{Kind: KindTerraformProvider, Name: label, Version: v,
					Ecosystem: EcoGo, Package: module, Source: f})
			}
		}
		for _, block := range blocks(text, "terraform") {
			if m := reReqVersion.FindStringSubmatch(block); m != nil {
				if v, ok := MinVersion(m[1]); ok {
					out = append(out, Component{Kind: KindTerraform, Name: "Terraform", Version: v,
						Ecosystem: EcoGo, Package: "github.com/hashicorp/terraform", Source: f})
				}
			}
		}
	}
	for _, pin := range []struct{ file, name, module string }{
		{".terraform-version", "Terraform", "github.com/hashicorp/terraform"},
		{".opentofu-version", "OpenTofu", "github.com/opentofu/opentofu"},
	} {
		p := filepath.Join(dir, pin.file)
		if data, err := readSmall(p); err == nil {
			if m := reNumVersion.FindStringSubmatch(strings.TrimSpace(string(data))); m != nil {
				out = append(out, Component{Kind: KindTerraform, Name: pin.name, Version: pad3(m[1]),
					Ecosystem: EcoGo, Package: pin.module, Source: p, Exact: strings.Count(m[1], ".") == 2})
			}
		}
	}
	return out
}

// TerraformBinaries asks the local terraform and tofu binaries for their version.
func TerraformBinaries(run Exec) []Component {
	var out []Component
	for _, b := range []struct{ cmd, module string }{
		{"terraform", "github.com/hashicorp/terraform"},
		{"tofu", "github.com/opentofu/opentofu"},
	} {
		s, err := run(b.cmd, "version")
		if err != nil {
			continue
		}
		if m := reTFBinary.FindStringSubmatch(s); m != nil {
			out = append(out, Component{Kind: KindTerraform, Name: m[1], Version: m[2],
				Ecosystem: EcoGo, Package: b.module, Source: b.cmd + " version", Exact: true})
		}
	}
	return out
}

// blocks returns the bodies of the blocks named name (balanced braces).
func blocks(text, name string) []string {
	var out []string
	re := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(name) + `\s*\{`)
	for _, loc := range re.FindAllStringIndex(text, -1) {
		depth := 0
		for i := loc[1] - 1; i < len(text); i++ {
			switch text[i] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					out = append(out, text[loc[1]:i])
					i = len(text)
				}
			}
		}
	}
	return out
}
