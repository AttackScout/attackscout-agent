package inventory

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/os/apk"
	"github.com/google/osv-scalibr/extractor/filesystem/os/dpkg"
	"github.com/google/osv-scalibr/extractor/filesystem/os/rpm"
	scalibrfs "github.com/google/osv-scalibr/fs"
)

// KindSystemPackage is a package of the operating system (dpkg, rpm, apk).
const KindSystemPackage = "system-package"

// KindWebServer is nginx, Apache httpd or IIS.
const KindWebServer = "web-server"

// systemDBs are the package databases read under the system root, with the
// extractor that parses them. Nothing is executed: the files are read.
var systemDBs = []struct {
	path string
	new  func(*cpb.PluginConfig) (filesystem.Extractor, error)
}{
	{"var/lib/dpkg/status", dpkg.New},
	{"lib/apk/db/installed", apk.New},
	{"var/lib/rpm/rpmdb.sqlite", rpm.New},
	{"var/lib/rpm/Packages.db", rpm.New},
	{"var/lib/rpm/Packages", rpm.New},
	{"usr/lib/sysimage/rpm/rpmdb.sqlite", rpm.New},
}

// SystemPackages reads the dpkg, apk and rpm databases under sysroot ("/"
// on a server). The OSV ecosystem (Debian, Ubuntu, Alpine, Red Hat, Rocky
// Linux, AlmaLinux...) comes from etc/os-release.
func SystemPackages(sysroot string) ([]Component, error) {
	if sysroot == "" {
		return nil, nil
	}
	sfs := scalibrfs.DirFS(sysroot)
	var out []Component
	for _, db := range systemDBs {
		full := filepath.Join(sysroot, filepath.FromSlash(db.path))
		info, err := os.Stat(full)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		e, err := db.new(&cpb.PluginConfig{})
		if err != nil {
			return out, err
		}
		f, err := os.Open(full)
		if err != nil {
			continue
		}
		inv, err := e.Extract(context.Background(), &filesystem.ScanInput{FS: sfs, Path: db.path, Root: sysroot, Info: info, Reader: f})
		_ = f.Close()
		if err != nil {
			return out, err
		}
		for _, p := range inv.Packages {
			eco := string(p.Ecosystem().Ecosystem)
			if p.Version == "" {
				continue
			}
			out = append(out, Component{Kind: KindSystemPackage, Name: p.Name, Version: p.Version, Ecosystem: eco,
				Package: p.Name, Source: full, Exact: true, Raw: p})
		}
	}
	return out, nil
}

// OSEcosystem returns the OSV ecosystem of the system under sysroot, from
// etc/os-release ("" when unknown).
func OSEcosystem(sysroot string) string {
	if sysroot == "" {
		return ""
	}
	data, err := readSmall(filepath.Join(sysroot, "etc", "os-release"))
	if err != nil {
		return ""
	}
	id := ""
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "ID="); ok {
			id = strings.Trim(v, `"'`)
		}
	}
	return map[string]string{"debian": "Debian", "ubuntu": "Ubuntu", "alpine": "Alpine", "rhel": "Red Hat",
		"rocky": "Rocky Linux", "almalinux": "AlmaLinux", "opensuse-leap": "openSUSE", "sles": "SUSE"}[id]
}

var (
	reNginxV  = regexp.MustCompile(`nginx/(\d+\.\d+\.\d+)`)
	reApacheV = regexp.MustCompile(`Apache/(\d+\.\d+\.\d+)`)
	reIISV    = regexp.MustCompile(`VersionString\s+REG_SZ\s+Version\s+(\d+\.\d+)`)
)

// WebServers asks nginx, Apache httpd and IIS for their version. The
// commands only print a version; they never touch the network.
func WebServers(run Exec) []Component {
	var out []Component
	if s, err := run("nginx", "-v"); s != "" || err == nil {
		if m := reNginxV.FindStringSubmatch(s); m != nil {
			out = append(out, Component{Kind: KindWebServer, Product: "nginx", Name: "nginx", Version: m[1], Source: "nginx -v", Exact: true})
		}
	}
	for _, bin := range []string{"apache2", "httpd"} {
		if s, _ := run(bin, "-v"); s != "" {
			if m := reApacheV.FindStringSubmatch(s); m != nil {
				out = append(out, Component{Kind: KindWebServer, Product: "apache", Name: "Apache httpd", Version: m[1], Source: bin + " -v", Exact: true})
				break
			}
		}
	}
	if s, _ := run("reg", "query", `HKLM\SOFTWARE\Microsoft\InetStp`, "/v", "VersionString"); s != "" {
		if m := reIISV.FindStringSubmatch(s); m != nil {
			out = append(out, Component{Kind: KindWebServer, Product: "iis", Name: "IIS", Version: m[1], Source: "registry InetStp", Exact: true})
		}
	}
	return out
}
