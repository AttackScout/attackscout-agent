package inventory

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestLockfilesMoreEcosystems(t *testing.T) {
	deps, err := Lockfiles(filepath.Join(td, "project-more"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []struct{ name, version, eco string }{
		{"django", "3.2.0", EcoPyPI},                                // poetry.lock
		{"rails", "6.1.0", EcoRubyGems},                             // Gemfile.lock
		{"rack", "2.2.3", EcoRubyGems},                              // Gemfile.lock
		{"golang.org/x/net", "0.10.0", EcoGo},                       // go.mod
		{"org.apache.logging.log4j:log4j-core", "2.14.1", EcoMaven}, // pom.xml
		{"github.com/gin-gonic/gin", "1.9.1", EcoGo},                // go.sum without go.mod
	} {
		c := find(deps, want.name)
		if c == nil {
			t.Errorf("%s not found in %+v", want.name, deps)
			continue
		}
		if c.Version != want.version || c.Ecosystem != want.eco {
			t.Errorf("%s: %s %s", want.name, c.Version, c.Ecosystem)
		}
	}
	for _, c := range deps {
		if strings.Contains(c.Version, "${") {
			t.Errorf("unresolved Maven property kept: %+v", c)
		}
	}
}

func TestGoSum(t *testing.T) {
	if GoSum(filepath.Join(td, "missing", "go.sum")) != nil {
		t.Error("missing file")
	}
	if !semverLess("1.6.0", "1.10.0") || semverLess("1.10.0", "1.9.1") || !semverLess("1.2", "1.2.1") {
		t.Error("semverLess")
	}
}

func TestSystemPackages(t *testing.T) {
	deb, err := SystemPackages(filepath.Join(td, "sysroot-debian"))
	if err != nil {
		t.Fatal(err)
	}
	c := find(deb, "openssl")
	if c == nil || c.Version != "3.0.11-1~deb12u1" || c.Ecosystem != "Debian" || c.Kind != KindSystemPackage || c.Raw == nil {
		t.Fatalf("dpkg: %+v", deb)
	}
	if find(deb, "removed-pkg") != nil {
		t.Error("a removed package is not installed")
	}
	apk, err := SystemPackages(filepath.Join(td, "sysroot-alpine"))
	if err != nil {
		t.Fatal(err)
	}
	if c := find(apk, "musl"); c == nil || c.Version != "1.2.4-r2" || c.Ecosystem != "Alpine" {
		t.Fatalf("apk: %+v", apk)
	}
	if none, err := SystemPackages(""); none != nil || err != nil {
		t.Error("empty sysroot must be skipped")
	}
	if got := OSEcosystem(filepath.Join(td, "sysroot-debian")); got != "Debian" {
		t.Error(got)
	}
	if OSEcosystem("") != "" || OSEcosystem(td) != "" {
		t.Error("unknown system")
	}
}

func TestWebServers(t *testing.T) {
	run := func(name string, args ...string) (string, error) {
		switch name {
		case "nginx":
			return "nginx version: nginx/1.24.0 (Ubuntu)", nil
		case "httpd":
			return "Server version: Apache/2.4.58 (Unix)\nServer built: x", nil
		case "reg":
			return "    VersionString    REG_SZ    Version 10.0", nil
		}
		return "", errors.New("not found")
	}
	got := WebServers(run)
	if len(got) != 3 || got[0].Product != "nginx" || got[0].Version != "1.24.0" ||
		got[1].Product != "apache" || got[1].Version != "2.4.58" || got[2].Product != "iis" || got[2].Version != "10.0" {
		t.Fatalf("%+v", got)
	}
	if WebServers(func(string, ...string) (string, error) { return "", errors.New("x") }) != nil {
		t.Error("nothing installed")
	}
}
