package scan

import (
	"encoding/xml"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/attackscout/attackscout-agent/internal/i18n"
)

// ConfFile is one configuration file, comments removed.
type ConfFile struct {
	Path string
	Text string
}

// IISConfig is what web.config says about headers and listings.
type IISConfig struct {
	Path            string
	Headers         map[string]string // lower-case name → value
	Removed         map[string]bool   // lower-case names removed
	DirectoryBrowse bool
	RemoveServer    bool
	Err             error // set when the file could not be parsed
}

// WebConfig is the web server configuration found on disk.
type WebConfig struct {
	NginxDir  string
	ApacheDir string
	Nginx     []ConfFile
	Apache    []ConfFile
	IIS       *IISConfig
	Certs     []string // certificate files named in the configuration
	Roots     []string // document roots named in the configuration
}

// Text returns every nginx and Apache configuration file, joined.
func (w WebConfig) Text() string {
	return joinText(append(append([]ConfFile{}, w.Nginx...), w.Apache...))
}

var (
	reNginxCert  = regexp.MustCompile(`(?m)^\s*ssl_certificate\s+"?([^;"\s]+)"?\s*;`)
	reNginxRoot  = regexp.MustCompile(`(?m)^\s*root\s+"?([^;"\s]+)"?\s*;`)
	reApacheCert = regexp.MustCompile(`(?mi)^\s*SSLCertificateFile\s+"?([^"\s]+)"?`)
	reApacheRoot = regexp.MustCompile(`(?mi)^\s*DocumentRoot\s+"?([^"\s]+)"?`)
	// disabled configuration lives in these directories
	disabledDirs = map[string]bool{"sites-available": true, "conf-available": true, "mods-available": true}
)

// LoadWebConfig reads nginx and Apache configuration directories, and the
// .htaccess and web.config files of the web root.
func LoadWebConfig(nginxDir, apacheDir, root string) WebConfig {
	w := WebConfig{NginxDir: nginxDir, ApacheDir: apacheDir}
	if nginxDir != "" {
		w.Nginx = readConfDir(nginxDir)
	}
	if apacheDir != "" {
		w.Apache = readConfDir(apacheDir)
	}
	if root != "" {
		p := filepath.Join(root, ".htaccess")
		if data, err := readSmall(p); err == nil && (apacheDir != "" || nginxDir == "") {
			w.Apache = append(w.Apache, ConfFile{Path: p, Text: stripComments(string(data))})
		}
		p = filepath.Join(root, "web.config")
		if _, err := os.Stat(p); err == nil {
			w.IIS = ParseWebConfig(p)
		}
	}
	for _, f := range w.Nginx {
		w.Certs = append(w.Certs, resolve(nginxDir, reNginxCert, f.Text)...)
		w.Roots = append(w.Roots, resolve(nginxDir, reNginxRoot, f.Text)...)
	}
	for _, f := range w.Apache {
		w.Certs = append(w.Certs, resolve(apacheDir, reApacheCert, f.Text)...)
		w.Roots = append(w.Roots, resolve(apacheDir, reApacheRoot, f.Text)...)
	}
	w.Certs, w.Roots = dedupe(w.Certs), dedupe(w.Roots)
	return w
}

func resolve(base string, re *regexp.Regexp, text string) []string {
	var out []string
	for _, m := range re.FindAllStringSubmatch(text, -1) {
		p := m[1]
		if strings.Contains(p, "$") {
			continue
		}
		if !filepath.IsAbs(p) && !strings.HasPrefix(p, "/") && base != "" {
			p = filepath.Join(base, filepath.FromSlash(p))
		}
		out = append(out, p)
	}
	return out
}

func readConfDir(dir string) []ConfFile {
	var out []ConfFile
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if disabledDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		parent := filepath.Base(filepath.Dir(p))
		if filepath.Ext(p) != ".conf" && parent != "sites-enabled" && parent != "conf.d" {
			return nil
		}
		if data, err := readSmall(p); err == nil {
			out = append(out, ConfFile{Path: p, Text: stripComments(string(data))})
		}
		return nil
	})
	return out
}

func stripComments(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		if j := strings.Index(l, "#"); j >= 0 {
			lines[i] = l[:j]
		}
	}
	return strings.Join(lines, "\n")
}

// --- IIS web.config ---

type xmlAdd struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

type xmlWebServer struct {
	Add             []xmlAdd `xml:"httpProtocol>customHeaders>add"`
	Remove          []xmlAdd `xml:"httpProtocol>customHeaders>remove"`
	DirectoryBrowse struct {
		Enabled string `xml:"enabled,attr"`
	} `xml:"directoryBrowse"`
	RequestFiltering struct {
		RemoveServerHeader string `xml:"removeServerHeader,attr"`
	} `xml:"security>requestFiltering"`
}

type xmlConfiguration struct {
	WebServer []xmlWebServer `xml:"system.webServer"`
	Locations []struct {
		WebServer []xmlWebServer `xml:"system.webServer"`
	} `xml:"location"`
}

// ParseWebConfig reads an IIS web.config with encoding/xml.
func ParseWebConfig(path string) *IISConfig {
	c := &IISConfig{Path: path, Headers: map[string]string{}, Removed: map[string]bool{}}
	data, err := readSmall(path)
	if err != nil {
		c.Err = err
		return c
	}
	var x xmlConfiguration
	if err := xml.Unmarshal(data, &x); err != nil {
		c.Err = err
		return c
	}
	all := x.WebServer
	for _, l := range x.Locations {
		all = append(all, l.WebServer...)
	}
	for _, ws := range all {
		for _, a := range ws.Add {
			c.Headers[strings.ToLower(a.Name)] = a.Value
		}
		for _, r := range ws.Remove {
			c.Removed[strings.ToLower(r.Name)] = true
		}
		if strings.EqualFold(ws.DirectoryBrowse.Enabled, "true") {
			c.DirectoryBrowse = true
		}
		if strings.EqualFold(ws.RequestFiltering.RemoveServerHeader, "true") {
			c.RemoveServer = true
		}
	}
	return c
}

// Text returns the custom headers as "name: value" lines, for header checks.
func (c *IISConfig) Text() string {
	keys := make([]string, 0, len(c.Headers))
	for k := range c.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s: %s\n", k, c.Headers[k])
	}
	return b.String()
}

// --- checks ---

type headerRule struct {
	id, header string
	any        []string
	severity   Severity
}

var headerRules = []headerRule{
	{"header-hsts-missing", "Strict-Transport-Security", []string{"strict-transport-security"}, Medium},
	{"header-csp-missing", "Content-Security-Policy", []string{"content-security-policy"}, Low},
	{"header-xcto-missing", "X-Content-Type-Options", []string{"x-content-type-options"}, Low},
	{"header-frame-missing", "X-Frame-Options / frame-ancestors", []string{"x-frame-options", "frame-ancestors"}, Low},
	{"header-referrer-missing", "Referrer-Policy", []string{"referrer-policy"}, Low},
}

var (
	reNginxTokens   = regexp.MustCompile(`(?m)^\s*server_tokens\s+off\s*;`)
	reNginxIndex    = regexp.MustCompile(`(?m)^\s*autoindex\s+on\s*;`)
	reApacheTokens  = regexp.MustCompile(`(?mi)^\s*ServerTokens\s+(Prod|ProductOnly)\b`)
	reApacheSigOff  = regexp.MustCompile(`(?mi)^\s*ServerSignature\s+Off\b`)
	reApacheOptions = regexp.MustCompile(`(?mi)^\s*Options\s+(.*)$`)
)

// CheckWebConfig checks security headers and disclosure settings of nginx,
// Apache and IIS.
func CheckWebConfig(w WebConfig) ([]Finding, Status, i18n.Msg) {
	if len(w.Nginx) == 0 && len(w.Apache) == 0 && w.IIS == nil {
		return nil, NotChecked, i18n.M("note.web.none")
	}
	var out []Finding
	note := i18n.Msg{}
	if len(w.Nginx) > 0 {
		text := joinText(w.Nginx)
		out = append(out, headerFindings("nginx", w.NginxDir, text, "fix.header.nginx")...)
		if !reNginxTokens.MatchString(text) {
			out = append(out, Finding{ID: "server-tokens", Severity: Low, Path: w.NginxDir,
				Title: i18n.M("web.nginx-tokens"), Fix: i18n.M("fix.nginx-tokens")})
		}
		for _, f := range w.Nginx {
			if reNginxIndex.MatchString(f.Text) {
				out = append(out, Finding{ID: "directory-listing", Severity: Medium, Path: f.Path,
					Title: i18n.M("web.nginx-autoindex"), Fix: i18n.M("fix.nginx-autoindex")})
			}
		}
	}
	if len(w.Apache) > 0 {
		text := joinText(w.Apache)
		dir := w.ApacheDir
		if dir == "" {
			dir = w.Apache[0].Path
		}
		out = append(out, headerFindings("Apache", dir, text, "fix.header.apache")...)
		if !reApacheTokens.MatchString(text) {
			out = append(out, Finding{ID: "server-tokens", Severity: Low, Path: dir,
				Title: i18n.M("web.apache-tokens"), Fix: i18n.M("fix.apache-tokens")})
		}
		if !reApacheSigOff.MatchString(text) {
			out = append(out, Finding{ID: "server-signature", Severity: Low, Path: dir,
				Title: i18n.M("web.apache-signature"), Fix: i18n.M("fix.apache-signature")})
		}
		for _, f := range w.Apache {
			for _, m := range reApacheOptions.FindAllStringSubmatch(f.Text, -1) {
				if optionsIndexes(m[1]) {
					out = append(out, Finding{ID: "directory-listing", Severity: Medium, Path: f.Path,
						Title: i18n.M("web.apache-indexes"), Fix: i18n.M("fix.apache-indexes")})
					break
				}
			}
		}
	}
	if c := w.IIS; c != nil {
		if c.Err != nil {
			note = i18n.M("note.web.iis-unparsed", c.Path)
			if len(w.Nginx) == 0 && len(w.Apache) == 0 {
				return out, NotChecked, note
			}
		} else {
			out = append(out, headerFindings("IIS", c.Path, c.Text(), "fix.header.iis")...)
			if !c.RemoveServer {
				out = append(out, Finding{ID: "server-tokens", Severity: Low, Path: c.Path,
					Title: i18n.M("web.iis-server"), Fix: i18n.M("fix.iis-server")})
			}
			if !c.Removed["x-powered-by"] {
				out = append(out, Finding{ID: "x-powered-by", Severity: Low, Path: c.Path,
					Title: i18n.M("web.iis-powered"), Fix: i18n.M("fix.iis-powered")})
			}
			if c.DirectoryBrowse {
				out = append(out, Finding{ID: "directory-listing", Severity: Medium, Path: c.Path,
					Title: i18n.M("web.iis-browse"), Fix: i18n.M("fix.iis-browse")})
			}
		}
	}
	return out, Pass, note
}

func optionsIndexes(opts string) bool {
	for _, o := range strings.Fields(opts) {
		if strings.EqualFold(o, "Indexes") || strings.EqualFold(o, "+Indexes") || strings.EqualFold(o, "All") {
			return true
		}
	}
	return false
}

func joinText(fs []ConfFile) string {
	var b strings.Builder
	for _, f := range fs {
		b.WriteString(f.Text)
		b.WriteByte('\n')
	}
	return b.String()
}

func headerFindings(server, where, text, fixKey string) []Finding {
	lower := strings.ToLower(text)
	var out []Finding
	for _, r := range headerRules {
		found := false
		for _, a := range r.any {
			if strings.Contains(lower, a) {
				found = true
			}
		}
		if !found {
			name := strings.SplitN(r.header, " ", 2)[0]
			out = append(out, Finding{ID: r.id, Severity: r.severity, Path: where,
				Title: i18n.M("web.header-missing", server, r.header),
				Fix:   i18n.M(fixKey, i18n.M("fix."+r.id), name)})
		}
	}
	return out
}

// readSmall reads a regular file of at most 1 MB.
func readSmall(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > 1<<20 {
		return nil, fmt.Errorf("%s: not a small regular file", path)
	}
	return os.ReadFile(path)
}
