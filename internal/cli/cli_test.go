package cli

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash/crc32"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attackscout/attackscout-agent/internal/report"
	"github.com/attackscout/attackscout-agent/internal/vulns"
)

const td = "../../testdata"

// guard replaces http.DefaultTransport: it counts every request and only
// lets loopback test servers through. Any other host fails the request.
type guard struct {
	calls atomic.Int64
	next  http.RoundTripper
}

func (g *guard) RoundTrip(r *http.Request) (*http.Response, error) {
	g.calls.Add(1)
	host, _, _ := net.SplitHostPort(r.URL.Host)
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return nil, errors.New("test guard: real network access to " + r.URL.Host)
	}
	return g.next.RoundTrip(r)
}

var netGuard = &guard{next: http.DefaultTransport}

func TestMain(m *testing.M) {
	http.DefaultTransport = netGuard
	os.Exit(m.Run())
}

const lodashVuln = `{"id":"GHSA-35jh-r3h4-6jhm","aliases":["CVE-2021-23337"],"summary":"Command injection in lodash",
"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}],
"affected":[{"package":{"ecosystem":"npm","name":"lodash"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}`

func npmZip(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	f, err := w.Create("GHSA-35jh-r3h4-6jhm.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte(lodashVuln)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func localDB(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := vulns.ArchivePath(dir, "npm")
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, npmZip(t), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func testEnv() env {
	return env{
		exec:  func(string, ...string) (string, error) { return "", os.ErrNotExist },
		now:   func() time.Time { return time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC) },
		goos:  "linux",
		getwd: func() (string, error) { return "", errors.New("no cwd") },
	}
}

func runT(t *testing.T, e env, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb, e)
	return code, out.String(), errb.String()
}

func TestCommands(t *testing.T) {
	e := testEnv()
	if c, _, errs := runT(t, e); c != ExitUsage || !strings.Contains(errs, "Usage") {
		t.Error("no args")
	}
	if c, _, errs := runT(t, e, "nope"); c != ExitUsage || !strings.Contains(errs, "unknown command") {
		t.Error("unknown command")
	}
	if c, out, _ := runT(t, e, "version"); c != ExitOK || out != "attackscout-agent "+Version+"\n" {
		t.Error(out)
	}
	if c, out, _ := runT(t, e, "help"); c != ExitOK || !strings.Contains(out, "--format") || strings.Contains(out, report.AuditURL) {
		t.Error("help")
	}
	if c, _, _ := runT(t, e, "db"); c != ExitUsage {
		t.Error("db without subcommand")
	}
	for _, bad := range [][]string{{"scan", "--fail-on", "severe"}, {"scan", "--lang", "de"}, {"scan", "--nope"}, {"db", "update", "--nope"}, {"scan", "--format", "xml"}, {"scan", "--output", "/nonexistent-dir/x/report.txt"}} {
		if c, _, _ := runT(t, e, bad...); c != ExitUsage {
			t.Errorf("%v accepted", bad)
		}
	}
}

// TestDefaultScanUsesNoNetwork runs the default path with a local database and
// checks that no HTTP request was attempted at all.
func TestDefaultScanUsesNoNetwork(t *testing.T) {
	before, refused := netGuard.calls.Load(), vulns.Refusals()
	db := localDB(t)
	code, out, errs := runT(t, testEnv(), "scan", "--root", filepath.Join(td, "wordpress"), "--project", filepath.Join(td, "project"),
		"--project", filepath.Join(td, "terraform"), "--nginx", filepath.Join(td, "nginx"), "--db", db)
	if code != ExitOK || errs != "" {
		t.Fatalf("code %d: %s", code, errs)
	}
	if netGuard.calls.Load() != before || vulns.Refusals() != refused {
		t.Fatalf("the default scan tried the network (%d requests)", netGuard.calls.Load()-before)
	}
	for _, want := range []string{"Network: nothing was sent", "CVE-2021-23337", "Upgrade lodash to 4.17.21 or later",
		"hashicorp/aws", "CVEs not checked for: Go, NuGet, Packagist, PyPI", "Next.js", "[CRITICAL] sensitive-env", report.AuditURL} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "not-a-real") {
		t.Fatal("a secret value was printed")
	}
}

func TestScanFailOnAndJSON(t *testing.T) {
	e := testEnv()
	args := []string{"scan", "--root", filepath.Join(td, "wordpress"), "--db", t.TempDir()}
	if c, _, _ := runT(t, e, append(args, "--fail-on", "high")...); c != ExitFindings {
		t.Errorf("--fail-on high: %d", c)
	}
	if c, _, _ := runT(t, e, append(args, "--fail-on", "none")...); c != ExitOK {
		t.Errorf("--fail-on none: %d", c)
	}
	c, out, _ := runT(t, e, append(args, "--json", "--lang", "fr")...)
	if c != ExitOK {
		t.Fatal(c)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if _, ok := got["external_audit"]; ok || strings.Contains(out, report.AuditURL) || got["lang"] != "fr" || got["cve_mode"] != "offline" {
		t.Errorf("%v", got)
	}
	found := false
	for _, ch := range got["checks"].([]any) {
		m := ch.(map[string]any)
		if m["id"] == "vulnerabilities" {
			found = true
			if m["status"] != "not_checked" || !strings.Contains(m["note"].(string), "CVE non vérifiées") {
				t.Errorf("without database the CVE check must say so: %v", m)
			}
		}
	}
	if !found {
		t.Error("no vulnerabilities check")
	}
	// text in French
	_, out, _ = runT(t, e, append(args, "--lang", "fr")...)
	if !strings.Contains(out, "Réseau : rien n'a été envoyé") {
		t.Error(out)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("closed") }

func TestScanWriteError(t *testing.T) {
	var errb bytes.Buffer
	if c := run([]string{"scan", "--db", t.TempDir()}, failWriter{}, &errb, testEnv()); c != ExitUsage {
		t.Error(c)
	}
}

func TestDetection(t *testing.T) {
	e := testEnv()
	e.nginx = []string{filepath.Join(td, "missing"), filepath.Join(td, "nginx")}
	e.apache = []string{filepath.Join(td, "apache")}
	e.roots = []string{filepath.Join(td, "missing"), filepath.Join(td, "wordpress")}
	_, out, _ := runT(t, e, "scan", "--db", t.TempDir())
	for _, want := range []string{"root: " + filepath.Join(td, "wordpress"), "nginx: " + filepath.Join(td, "nginx"), "apache: " + filepath.Join(td, "apache")} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	// current directory
	e = testEnv()
	e.getwd = func() (string, error) { return filepath.Join(td, "drupal7"), nil }
	if got := detectRoot("", "", e); got != "" {
		t.Errorf("drupal7 fixture has no site marker: %q", got)
	}
	e.getwd = func() (string, error) { return filepath.Join(td, "wordpress"), nil }
	if got := detectRoot("", "", e); got != filepath.Join(td, "wordpress") {
		t.Error(got)
	}
	if firstDir([]string{filepath.Join(td, "wordpress", "index.php")}) != "" {
		t.Error("a file is not a directory")
	}
	d := defaultEnv()
	if len(d.nginx) == 0 || len(d.roots) == 0 || d.exec == nil {
		t.Error("default environment")
	}
}

func TestOnline(t *testing.T) {
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := new(bytes.Buffer)
		_, _ = b.ReadFrom(r.Body)
		bodies = append(bodies, b.String())
		switch r.URL.Path {
		case "/v1/querybatch":
			var q struct {
				Queries []json.RawMessage `json:"queries"`
			}
			_ = json.Unmarshal(b.Bytes(), &q)
			var res []string
			for _, qq := range q.Queries {
				if strings.Contains(string(qq), `"lodash"`) {
					res = append(res, `{"vulns":[{"id":"GHSA-35jh-r3h4-6jhm","modified":"2026-01-01T00:00:00Z"}]}`)
				} else {
					res = append(res, `{}`)
				}
			}
			_, _ = w.Write([]byte(`{"results":[` + strings.Join(res, ",") + `]}`))
		case "/v1/vulns/GHSA-35jh-r3h4-6jhm":
			_, _ = w.Write([]byte(lodashVuln))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	old := osvAPI
	osvAPI = srv.URL
	defer func() { osvAPI = old }()
	code, out, _ := runT(t, testEnv(), "scan", "--online", "--root", filepath.Join(td, "wordpress"), "--project", filepath.Join(td, "project"))
	if code != ExitOK || !strings.Contains(out, "--online") || !strings.Contains(out, "CVE-2021-23337") {
		t.Fatalf("%d\n%s", code, out)
	}
	all := strings.Join(bodies, "\n")
	for _, leak := range []string{"testdata", "wordpress", "Hello Forms", "example.com", "WordPress"} {
		if strings.Contains(all, leak) {
			t.Errorf("--online leaked %q", leak)
		}
	}
}

func TestDBUpdate(t *testing.T) {
	data := npmZip(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/kev":
			_, _ = w.Write([]byte(`{"vulnerabilities":[{"cveID":"CVE-2021-23337","dateAdded":"2024-01-01","knownRansomwareCampaignUse":"Unknown"}]}`))
			return
		case strings.HasPrefix(r.URL.Path, "/eol/"):
			_, _ = w.Write([]byte(`{"result":{"releases":[{"name":"8.3","isEol":false,"eolFrom":"2027-12-31","latest":{"name":"8.3.99"}}]}}`))
			return
		case r.URL.Path != "/npm/all.zip":
			http.NotFound(w, r)
			return
		}
		sum := make([]byte, 4)
		binary.BigEndian.PutUint32(sum, crc32.Checksum(data, crc32.MakeTable(crc32.Castagnoli)))
		w.Header().Set("X-Goog-Hash", "crc32c="+base64.StdEncoding.EncodeToString(sum))
		_, _ = w.Write(data)
	}))
	defer srv.Close()
	old := archiveHost
	oldKEV, oldEOL := kevURL, eolBase
	archiveHost, kevURL, eolBase = srv.URL, srv.URL+"/kev", srv.URL+"/eol"
	defer func() { archiveHost, kevURL, eolBase = old, oldKEV, oldEOL }()
	dir := t.TempDir()
	code, out, errs := runT(t, testEnv(), "db", "update", "--db", dir, "--ecosystems", "npm, PyPI,")
	if code != ExitFindings || !strings.Contains(out, "npm: ") || !strings.Contains(errs, "PyPI: ") {
		t.Fatalf("%d %q %q", code, out, errs)
	}
	code, _, _ = runT(t, testEnv(), "db", "update", "--db", dir, "--ecosystems", "npm")
	if code != ExitOK {
		t.Fatal(code)
	}
	// the downloaded database is then used offline
	before := netGuard.calls.Load()
	_, out, _ = runT(t, testEnv(), "scan", "--project", filepath.Join(td, "project"), "--db", dir)
	if !strings.Contains(out, "CVE-2021-23337") || netGuard.calls.Load() != before {
		t.Fatalf("offline scan after update:\n%s", out)
	}
	// the KEV list marks the CVE as exploited, the endoflife.date data is used
	if !strings.Contains(out, "EXPLOITED IN THE WILD") || !strings.Contains(out, "1 vulnerabilities are exploited") {
		t.Fatalf("KEV not applied:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(dir, "endoflife", "php.json")); err != nil {
		t.Fatal(err)
	}
}

func TestRunPublic(t *testing.T) {
	var out, errb bytes.Buffer
	if Run([]string{"version"}, &out, &errb) != ExitOK {
		t.Error("Run")
	}
}

func TestFormatsAndAuditLink(t *testing.T) {
	db := localDB(t)
	proj := filepath.Join(td, "project")
	// text: the link is shown by default, hidden by --no-audit-link
	_, out, _ := runT(t, testEnv(), "scan", "--project", proj, "--db", db)
	if !strings.Contains(out, report.AuditURL) || !strings.Contains(out, "utm_source=") {
		t.Fatalf("audit link missing:\n%s", out)
	}
	_, out, _ = runT(t, testEnv(), "scan", "--project", proj, "--db", db, "--no-audit-link")
	if strings.Contains(out, "attackscout.com") {
		t.Fatalf("audit link not hidden:\n%s", out)
	}
	// SARIF, written to a file
	file := filepath.Join(t.TempDir(), "r.sarif")
	code, out, _ := runT(t, testEnv(), "scan", "--project", proj, "--db", db, "--format", "sarif", "--output", file, "--fail-on", "high")
	if code != ExitFindings || out != "" {
		t.Fatalf("%d %q", code, out)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var s map[string]any
	if err := json.Unmarshal(data, &s); err != nil || s["version"] != "2.1.0" || strings.Contains(string(data), report.AuditURL) {
		t.Fatalf("%v %s", err, data)
	}
	if !strings.Contains(string(data), "CVE-2021-23337") {
		t.Fatal("CVE missing from SARIF")
	}
	// --fail-on thresholds
	for sev, want := range map[string]int{"critical": ExitOK, "high": ExitFindings, "medium": ExitFindings} {
		if c, _, _ := runT(t, testEnv(), "scan", "--project", proj, "--db", db, "--format", "json", "--fail-on", sev); c != want {
			t.Errorf("--fail-on %s: %d", sev, c)
		}
	}
}
