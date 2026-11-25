package scan

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/attackscout/attackscout-agent/internal/i18n"
)

// maxPermFindings caps the findings per permission rule; the rest is counted.
const maxPermFindings = 20

// secretFiles must not be readable by every local user.
var secretFiles = map[string]bool{"wp-config.php": true, ".env": true, "settings.php": true, "configuration.php": true, "parameters.php": true, "auth.json": true}

// CheckPerms checks Unix permissions under the web root.
func CheckPerms(root string) []Finding {
	return CheckPermsFS(os.DirFS(root), root)
}

// CheckPermsFS checks permissions in fsys; root is only used to print paths.
func CheckPermsFS(fsys fs.FS, root string) []Finding {
	var out []Finding
	extra := map[string]int{}
	add := func(f Finding) {
		n := 0
		for _, o := range out {
			if o.ID == f.ID {
				n++
			}
		}
		if n >= maxPermFindings {
			extra[f.ID]++
			return
		}
		out = append(out, f)
	}
	count := 0
	_ = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		count++
		if count > maxFiles {
			return fs.SkipAll
		}
		info, err := d.Info()
		if err != nil || info.Mode()&fs.ModeSymlink != 0 {
			return nil
		}
		mode := info.Mode()
		perm := mode.Perm()
		full := filepath.Join(root, filepath.FromSlash(p))
		switch {
		case d.IsDir() && perm == 0o777:
			add(Finding{ID: "perm-dir-777", Severity: High, Path: full,
				Title: i18n.M("perm.dir777", p), Fix: i18n.M("fix.perm-dir-777")})
		case d.IsDir() && perm&0o002 != 0 && mode&fs.ModeSticky == 0:
			add(Finding{ID: "perm-dir-world-writable", Severity: High, Path: full,
				Title: i18n.M("perm.dir-ww", p, fmt.Sprintf("%04o", perm)), Fix: i18n.M("fix.perm-dir-world-writable")})
		case !d.IsDir() && perm&0o002 != 0:
			add(Finding{ID: "perm-file-world-writable", Severity: High, Path: full,
				Title: i18n.M("perm.file-ww", p, fmt.Sprintf("%04o", perm)), Fix: i18n.M("fix.perm-file-world-writable")})
		}
		if !d.IsDir() && secretFiles[strings.ToLower(path.Base(p))] && perm&0o004 != 0 {
			add(Finding{ID: "perm-secret-world-readable", Severity: Medium, Path: full,
				Title: i18n.M("perm.secret-wr", p, fmt.Sprintf("%04o", perm)), Fix: i18n.M("fix.perm-secret-world-readable")})
		}
		if d.IsDir() && p != "." && (skipDirs[d.Name()] || strings.Count(p, "/") >= maxDepth) {
			return fs.SkipDir
		}
		return nil
	})
	for _, id := range []string{"perm-dir-777", "perm-dir-world-writable", "perm-file-world-writable", "perm-secret-world-readable"} {
		if n := extra[id]; n > 0 {
			out = append(out, Finding{ID: id, Severity: Info, Title: i18n.M("perm.more", n, id)})
		}
	}
	return out
}
