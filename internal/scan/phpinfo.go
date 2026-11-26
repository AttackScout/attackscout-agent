package scan

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/attackscout/attackscout-agent/internal/i18n"
)

// phpinfo pages are searched in small PHP files near the top of the web root.
const (
	phpinfoMaxDepth = 3
	phpinfoMaxSize  = 64 << 10
)

var (
	rePHPInfoCall = regexp.MustCompile(`(?i)\bphpinfo\s*\(`)
	// phpinfoSkip: code of the CMS and libraries, never a test page.
	phpinfoSkip = map[string]bool{"node_modules": true, "vendor": true, "wp-includes": true, "wp-admin": true, "core": true, "libraries": true}
)

// CheckPHPInfo reports PHP files that call phpinfo() under any name: such a
// page prints the configuration, paths and environment of the server. The
// files named phpinfo.php or info.php are already reported by name.
func CheckPHPInfo(root string) []Finding {
	var out []Finding
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || path == root {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if phpinfoSkip[strings.ToLower(d.Name())] || strings.HasPrefix(d.Name(), ".") || strings.Count(rel, "/") >= phpinfoMaxDepth {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.EqualFold(filepath.Ext(path), ".php") {
			return nil
		}
		if r := classify(d.Name(), false, false); r != nil && r.id == rulePHPInfo.id {
			return nil
		}
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() > phpinfoMaxSize {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil || !rePHPInfoCall.Match(stripPHPCommentsBytes(data)) {
			return nil
		}
		out = append(out, Finding{ID: "phpinfo-exposed", Severity: Medium, Path: path, Certainty: "high",
			Title: i18n.M("phpinfo.found", rel), Fix: i18n.M("fix.sensitive-phpinfo")})
		return nil
	})
	return out
}

func stripPHPCommentsBytes(b []byte) []byte { return []byte(stripPHPComments(string(b))) }
