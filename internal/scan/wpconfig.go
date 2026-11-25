package scan

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/attackscout/attackscout-cli/internal/i18n"
)

var wpSalts = []string{"AUTH_KEY", "SECURE_AUTH_KEY", "LOGGED_IN_KEY", "NONCE_KEY", "AUTH_SALT", "SECURE_AUTH_SALT", "LOGGED_IN_SALT", "NONCE_SALT"}

var reDefine = regexp.MustCompile(`(?i)define\(\s*['"]([A-Z_]+)['"]\s*,\s*(.+?)\s*\)\s*;`)

// FindWPConfig returns wp-config.php in the web root or, as WordPress
// allows, in its parent directory.
func FindWPConfig(root string) string {
	for _, p := range []string{filepath.Join(root, "wp-config.php"), filepath.Join(filepath.Dir(filepath.Clean(root)), "wp-config.php")} {
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			return p
		}
	}
	return ""
}

// parseDefines returns the raw value of each define(). Values stay in memory
// and are never printed.
func parseDefines(src string) map[string]string {
	out := map[string]string{}
	for _, m := range reDefine.FindAllStringSubmatch(stripPHPComments(src), -1) {
		out[strings.ToUpper(m[1])] = m[2]
	}
	return out
}

// rePHPComment matches whole-line comments only: secret values may contain
// "//" or "/*", so inline comments are left alone.
var rePHPComment = regexp.MustCompile(`(?m)^[ \t]*(//|#|\*|/\*)[^\n]*$`)

func stripPHPComments(s string) string { return rePHPComment.ReplaceAllString(s, "") }

func unquote(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && (v[0] == '\'' || v[0] == '"') && v[len(v)-1] == v[0] {
		return v[1 : len(v)-1], true
	}
	return v, false
}

func isTrue(v string, ok bool) bool {
	if !ok {
		return false
	}
	s, _ := unquote(v)
	s = strings.ToLower(s)
	return s == "true" || s == "1"
}

// CheckWPConfig checks keys, salts and debug settings of wp-config.php.
func CheckWPConfig(root string) []Finding {
	path := FindWPConfig(root)
	if path == "" {
		return nil
	}
	data, err := readSmall(path)
	if err != nil {
		return []Finding{{ID: "wpconfig-unreadable", Severity: Info, Path: path, Title: i18n.M("wp.unreadable")}}
	}
	defs := parseDefines(string(data))
	var out []Finding
	var missing, weak []string
	for _, k := range wpSalts {
		v, ok := defs[k]
		if !ok {
			missing = append(missing, k)
			continue
		}
		s, literal := unquote(v)
		if literal && (s == "" || strings.EqualFold(s, "put your unique phrase here")) {
			weak = append(weak, k)
		}
	}
	if len(weak) > 0 {
		out = append(out, Finding{ID: "wpconfig-salt-default", Severity: Critical, Path: path,
			Title: i18n.M("wp.salt-default", strings.Join(weak, ", ")), Fix: i18n.M("fix.wpconfig-salt-default")})
	}
	if len(missing) > 0 {
		out = append(out, Finding{ID: "wpconfig-salt-missing", Severity: High, Path: path,
			Title: i18n.M("wp.salt-missing", strings.Join(missing, ", ")), Fix: i18n.M("fix.wpconfig-salt-missing")})
	}
	debug, hasDebug := defs["WP_DEBUG"]
	display, hasDisplay := defs["WP_DEBUG_DISPLAY"]
	debugOn := isTrue(debug, hasDebug)
	if debugOn {
		out = append(out, Finding{ID: "wpconfig-debug", Severity: Medium, Path: path,
			Title: i18n.M("wp.debug"), Fix: i18n.M("fix.wpconfig-debug")})
	}
	if isTrue(display, hasDisplay) || (debugOn && !hasDisplay) {
		out = append(out, Finding{ID: "wpconfig-debug-display", Severity: High, Path: path,
			Title: i18n.M("wp.debug-display"), Fix: i18n.M("fix.wpconfig-debug-display")})
	}
	if v, ok := defs["DISALLOW_FILE_EDIT"]; !isTrue(v, ok) {
		out = append(out, Finding{ID: "wpconfig-file-edit", Severity: Low, Path: path,
			Title: i18n.M("wp.file-edit"), Fix: i18n.M("fix.wpconfig-file-edit")})
	}
	return out
}
