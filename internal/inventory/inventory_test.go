package inventory

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const td = "../../testdata"

func find(cs []Component, name string) *Component {
	for i := range cs {
		if cs[i].Name == name {
			return &cs[i]
		}
	}
	return nil
}

func noExec(string, ...string) (string, error) { return "", errors.New("absent") }

func fakeExec(out map[string]string) Exec {
	return func(name string, args ...string) (string, error) {
		if s, ok := out[name+" "+strings.Join(args, " ")]; ok {
			return s, nil
		}
		return "", errors.New("absent")
	}
}

func TestWordPress(t *testing.T) {
	cs := CMS(filepath.Join(td, "wordpress"))
	wp := find(cs, "WordPress")
	if wp == nil || wp.Version != "6.4.2" || wp.Product != "wordpress" || wp.Ecosystem != "" || !wp.Exact {
		t.Fatalf("core: %+v", wp)
	}
	p := find(cs, "Hello Forms")
	if p == nil || p.Version != "2.3.1" || p.Kind != KindCMSPlugin || p.Certainty() != "high" {
		t.Fatalf("plugin: %+v", p)
	}
	s := find(cs, "Single File")
	if s == nil || s.Version != "" || s.Exact {
		t.Fatalf("plugin without version: %+v", s)
	}
	th := find(cs, "Simple Theme")
	if th == nil || th.Version != "1.0.4" || th.Kind != KindCMSTheme {
		t.Fatalf("theme: %+v", th)
	}
}

func TestDrupal(t *testing.T) {
	cs := CMS(filepath.Join(td, "drupal"))
	core := find(cs, "Drupal")
	if core == nil || core.Version != "10.2.3" || core.Package != "drupal/core" || core.Ecosystem != EcoPackagist {
		t.Fatalf("core: %+v", core)
	}
	tok := find(cs, "Token")
	if tok == nil || tok.Version != "1.13.0" || tok.Package != "drupal/token" || tok.Kind != KindCMSModule {
		t.Fatalf("module: %+v", tok)
	}
	th := find(cs, "Olivero Plus")
	if th == nil || th.Version != "2.1.0-beta2" || th.Kind != KindCMSTheme {
		t.Fatalf("theme: %+v", th)
	}
	if find(cs, "My module") != nil {
		t.Error("custom module without release must be skipped")
	}
	d7 := CMS(filepath.Join(td, "drupal7"))
	if len(d7) != 1 || d7[0].Version != "7.98" || d7[0].Ecosystem != "" {
		t.Fatalf("drupal 7: %+v", d7)
	}
}

func TestJoomlaPrestaShop(t *testing.T) {
	cs := CMS(filepath.Join(td, "joomla"))
	if j := find(cs, "Joomla"); j == nil || j.Version != "4.4.3" || j.Package != "joomla/joomla-cms" {
		t.Fatalf("joomla: %+v", cs)
	}
	for name, kind := range map[string]string{"COM_EXAMPLE": KindCMSExtension, "plg_system_example": KindCMSExtension, "example_tpl": KindCMSTheme} {
		if c := find(cs, name); c == nil || c.Kind != kind {
			t.Errorf("%s: %+v", name, c)
		}
	}
	if find(cs, "not an extension") != nil {
		t.Error("config.xml is not a manifest")
	}
	ps := CMS(filepath.Join(td, "prestashop"))
	if len(ps) != 1 || ps[0].Version != "8.1.5" || ps[0].Package != "prestashop/prestashop" {
		t.Fatalf("prestashop: %+v", ps)
	}
	if ps16 := CMS(filepath.Join(td, "prestashop16")); len(ps16) != 1 || ps16[0].Version != "1.6.1.24" {
		t.Fatalf("prestashop 1.6: %+v", ps16)
	}
	if len(CMS(t.TempDir())) != 0 {
		t.Error("empty directory")
	}
}

func TestDrupalVersion(t *testing.T) {
	for in, want := range map[string]string{"8.x-1.13": "1.13.0", "2.1.0": "2.1.0", "8.x-2.0-rc1": "2.0.0-rc1", "3.2": "3.2.0"} {
		if got := drupalVersion(in); got != want {
			t.Errorf("%s: %s", in, got)
		}
	}
}

func TestLockfiles(t *testing.T) {
	cs, err := Lockfiles(filepath.Join(td, "project"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		eco   string
		exact bool
	}{
		"lodash": {EcoNPM, true}, "guzzlehttp/guzzle": {EcoPackagist, true}, "django": {EcoPyPI, true},
		"requests": {EcoPyPI, false}, "Newtonsoft.Json": {EcoNuGet, true}, "Serilog": {EcoNuGet, false},
		"System.Text.Json": {EcoNuGet, true},
	}
	for name, w := range want {
		c := find(cs, name)
		if c == nil || c.Ecosystem != w.eco || c.Exact != w.exact || c.Raw == nil || c.Pkg() != c.Raw {
			t.Errorf("%s: %+v", name, c)
		}
	}
	for dir, name := range map[string]string{"project-yarn1": "minimist", "project-berry": "axios", "project-pnpm": "express"} {
		cs, err := Lockfiles(filepath.Join(td, dir))
		if err != nil || find(cs, name) == nil {
			t.Errorf("%s: %+v %v", dir, cs, err)
		}
	}
}

func TestFrameworks(t *testing.T) {
	r := Collect(Options{Root: filepath.Join(td, "project"), Exec: noExec})
	next := find(r.Components, "Next.js")
	react := find(r.Components, "React")
	if next == nil || next.Version != "13.5.0" || next.Product != "nextjs" || next.Kind != KindFramework {
		t.Fatalf("next: %+v", next)
	}
	if react == nil || react.Version != "18.2.0" {
		t.Fatalf("react: %+v", react)
	}
	if find(r.Components, "react") != nil || find(r.Components, "next") != nil {
		t.Error("frameworks must not be listed twice")
	}
	// node_modules only
	dir := t.TempDir()
	for name, body := range map[string]string{
		"react": `{"name":"react","version":"19.1.0"}`,
		"next":  `{"name":"not-next","version":"1.0.0"}`,
	} {
		p := filepath.Join(dir, "node_modules", name)
		if err := os.MkdirAll(p, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, "package.json"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fw := Frameworks(dir, nil)
	if len(fw) != 1 || fw[0].Name != "React" || fw[0].Version != "19.1.0" || !fw[0].Exact {
		t.Fatalf("node_modules: %+v", fw)
	}
}

func TestRuntimes(t *testing.T) {
	ex := fakeExec(map[string]string{
		"php -v":                 "PHP 8.1.2-1ubuntu2.14 (cli) (built: Aug 18 2023)",
		"node --version":         "v20.11.1\n",
		"dotnet --list-runtimes": "Microsoft.AspNetCore.App 8.0.4 [/usr/share/dotnet]\nMicrosoft.NETCore.App 8.0.4 [/usr/share/dotnet]\nMicrosoft.NETCore.App 6.0.29 [/x]\n",
	})
	cs := Runtimes(Options{Exec: ex})
	if len(cs) != 4 || cs[0].Version != "8.1.2" || cs[1].Version != "20.11.1" || cs[2].Version != "8.0.4" || cs[3].Version != "6.0.29" {
		t.Fatalf("%+v", cs)
	}
	for _, c := range cs {
		if !c.Exact || c.Kind != KindRuntime {
			t.Errorf("%+v", c)
		}
	}
	// hints only
	hint := t.TempDir()
	for _, d := range []string{"7.4", "8.2", "conf.d"} {
		if err := os.MkdirAll(filepath.Join(hint, d), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	cs = Runtimes(Options{Exec: noExec, Root: filepath.Join(td, "project"), Projects: []string{filepath.Join(td, "project", "app")},
		PHPHintDirs: []string{hint, filepath.Join(hint, "missing")}, ConfigText: "fastcgi_pass unix:/run/php/php8.3-fpm.sock;"})
	var got []string
	for _, c := range cs {
		if c.Exact {
			t.Errorf("hint must be medium certainty: %+v", c)
		}
		got = append(got, c.Product+" "+c.Version)
	}
	if strings.Join(got, ",") != "php 7.4,php 8.2,php 8.3,nodejs 20.11.1,dotnet 6.0" {
		t.Fatalf("%v", got)
	}
	if len(Runtimes(Options{Exec: fakeExec(map[string]string{"php -v": "garbage", "node --version": "x", "dotnet --list-runtimes": "none"})})) != 0 {
		t.Error("unparsable output must be ignored")
	}
}

func TestTerraform(t *testing.T) {
	cs := Terraform(filepath.Join(td, "terraform"))
	want := map[string]struct {
		version, module string
		exact           bool
	}{
		"hashicorp/aws":         {"5.31.0", "github.com/hashicorp/terraform-provider-aws", true},
		"example-org/widget":    {"0.4.2", "github.com/example-org/terraform-provider-widget", true},
		"hashicorp/random":      {"3.1.0", "github.com/hashicorp/terraform-provider-random", false},
		"hashicorp/legacy":      {"2.0.0", "github.com/hashicorp/terraform-provider-legacy", false},
		"cloudflare/cloudflare": {"4.20.0", "github.com/cloudflare/terraform-provider-cloudflare", false},
	}
	for name, w := range want {
		c := find(cs, name)
		if c == nil || c.Version != w.version || c.Package != w.module || c.Exact != w.exact || c.Ecosystem != EcoGo {
			t.Errorf("%s: %+v", name, c)
		}
	}
	if find(cs, "hashicorp/anything") != nil {
		t.Error("a provider without version constraint has no version")
	}
	n := 0
	for _, c := range cs {
		if c.Name == "hashicorp/aws" {
			n++
		}
		if c.Kind == KindTerraform {
			switch c.Source[len(c.Source)-7:] {
			case "main.tf":
				if c.Version != "1.5.0" || c.Exact {
					t.Errorf("required_version: %+v", c)
				}
			}
		}
	}
	if n != 1 {
		t.Errorf("the lock file wins over required_providers: %d entries", n)
	}
	tofu := find(cs, "OpenTofu")
	if tofu == nil || tofu.Version != "1.6.0" || tofu.Exact || tofu.Package != "github.com/opentofu/opentofu" {
		t.Errorf("opentofu pin: %+v", tofu)
	}
	bins := TerraformBinaries(fakeExec(map[string]string{
		"terraform version": "Terraform v1.7.4\non linux_amd64\n",
		"tofu version":      "OpenTofu v1.6.2\n",
	}))
	if len(bins) != 2 || bins[0].Version != "1.7.4" || bins[1].Package != "github.com/opentofu/opentofu" || !bins[0].Exact {
		t.Fatalf("binaries: %+v", bins)
	}
	if len(TerraformBinaries(fakeExec(map[string]string{"terraform version": "nope"}))) != 0 {
		t.Error("garbage version")
	}
}

func TestMinVersion(t *testing.T) {
	cases := map[string]string{
		"~> 5.0": "5.0.0", ">= 1.5.0, < 2.0.0": "1.5.0", "= 1.2.3": "1.2.3", "1.2": "1.2.0",
		">= 1.0, >= 1.4": "1.4.0", "> 2.1": "2.1.0", "< 3.0": "", "": "", "!= 1.0": "", ">= 1.10, >= 1.9": "1.10.0",
	}
	for in, want := range cases {
		got, ok := MinVersion(in)
		if got != want || ok != (want != "") {
			t.Errorf("%q: %q %v", in, got, ok)
		}
	}
	if l, m := providerModule("aws"); l != "hashicorp/aws" || m != "github.com/hashicorp/terraform-provider-aws" {
		t.Error(l, m)
	}
	if l, _ := providerModule("registry.opentofu.org/Example-Org/Thing"); l != "example-org/thing" {
		t.Error(l)
	}
}

func TestCollect(t *testing.T) {
	r := Collect(Options{Root: filepath.Join(td, "wordpress"), Projects: []string{filepath.Join(td, "terraform"), filepath.Join(td, "wordpress")}})
	if find(r.Components, "WordPress") == nil || find(r.Components, "hashicorp/aws") == nil {
		t.Fatalf("%+v", r.Components)
	}
	for i := 1; i < len(r.Components); i++ {
		if kindRank(r.Components[i-1].Kind) > kindRank(r.Components[i].Kind) {
			t.Fatal("components must be sorted by kind")
		}
	}
	if kindRank("other") != len(kindOrder) {
		t.Error("unknown kind")
	}
}

func TestHelpers(t *testing.T) {
	if EcosystemOfPURL("composer") != EcoPackagist || EcosystemOfPURL("deb") != "" || PURLType(EcoGo) != "golang" {
		t.Error("purl mapping")
	}
	c := Component{Name: "x", Version: "1", Ecosystem: EcoNPM, Package: "x"}
	if p := c.Pkg(); p.PURLType != "npm" || p.Name != "x" || c.Certainty() != "medium" {
		t.Errorf("%+v", p)
	}
	if _, err := LocalExec("attackscout-cli-no-such-binary"); err == nil {
		t.Error("missing binary")
	}
	big := filepath.Join(t.TempDir(), "big")
	if err := os.WriteFile(big, make([]byte, 2<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSmall(big); err == nil {
		t.Error("big file accepted")
	}
	if _, err := Lockfiles(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Log("scalibr accepts a missing root")
	}
}

func TestQuietLogger(t *testing.T) {
	q := quiet{}
	q.Errorf("x")
	q.Error("x")
	q.Warnf("x")
	q.Warn("x")
	q.Infof("x")
	q.Info("x")
	q.Debugf("x")
	q.Debug("x")
}
