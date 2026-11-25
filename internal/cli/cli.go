// Package cli parses the command line and runs the commands.
package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/attackscout/attackscout-agent/internal/i18n"
	"github.com/attackscout/attackscout-agent/internal/inventory"
	"github.com/attackscout/attackscout-agent/internal/report"
	"github.com/attackscout/attackscout-agent/internal/scan"
	"github.com/attackscout/attackscout-agent/internal/vulns"
)

// Version is set at build time with -ldflags "-X ...cli.Version=x.y.z".
var Version = "0.1.0"

// Exit codes.
const (
	ExitOK       = 0
	ExitFindings = 1 // a finding reached --fail-on
	ExitUsage    = 2
)

// Remote locations, replaced by tests with local servers.
var (
	osvAPI      = vulns.DefaultAPI
	archiveHost = vulns.DefaultArchiveHost
)

// Environment of a run, replaced by tests.
type env struct {
	exec    inventory.Exec
	now     func() time.Time
	goos    string
	getwd   func() (string, error)
	nginx   []string
	apache  []string
	roots   []string
	phpDirs []string
}

func defaultEnv() env {
	e := env{exec: inventory.LocalExec, now: time.Now, goos: runtime.GOOS, getwd: os.Getwd}
	if e.goos == "windows" {
		e.nginx = []string{`C:\nginx\conf`}
		e.apache = []string{`C:\Apache24\conf`}
		e.roots = []string{`C:\inetpub\wwwroot`}
		return e
	}
	e.nginx = []string{"/etc/nginx", "/usr/local/etc/nginx", "/opt/homebrew/etc/nginx"}
	e.apache = []string{"/etc/apache2", "/etc/httpd", "/usr/local/etc/httpd", "/opt/homebrew/etc/httpd"}
	e.roots = []string{"/var/www/html", "/srv/www", "/usr/share/nginx/html", "/var/www"}
	e.phpDirs = []string{"/etc/php", "/etc/opt/remi"}
	return e
}

const usage = `attackscout-agent checks a website from inside its server. Read only, no network by default.

Usage:
  attackscout-agent scan [flags]       scan the server
  attackscout-agent db update [flags]  download the OSV databases (network)
  attackscout-agent version            print the version

Scan flags:
  --root DIR       web root (default: detected)
  --project DIR    extra project directory with lockfiles or Terraform (repeatable)
  --nginx DIR      nginx configuration directory (default: detected)
  --apache DIR     Apache configuration directory (default: detected)
  --cert FILE      PEM certificate to check (repeatable)
  --json           JSON output
  --fail-on SEV    exit 1 when a finding is at least info, low, medium, high or critical
  --lang LANG      en (default) or fr
  --online         query api.osv.dev (sends package names, versions and ecosystems only)
  --db DIR         OSV database directory (default: user cache)

db update flags:
  --db DIR         OSV database directory (default: user cache)
  --ecosystems L   comma-separated list (default: npm,Packagist,PyPI,NuGet,Go)

Free external audit: ` + report.AuditURL + "\n"

// Run executes the command line and returns the exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	return run(args, stdout, stderr, defaultEnv())
}

func run(args []string, stdout, stderr io.Writer, e env) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return ExitUsage
	}
	switch args[0] {
	case "scan":
		return runScan(args[1:], stdout, stderr, e)
	case "db":
		if len(args) > 1 && args[1] == "update" {
			return runDBUpdate(args[2:], stdout, stderr)
		}
		_, _ = fmt.Fprint(stderr, usage)
		return ExitUsage
	case "version", "--version", "-v":
		_, _ = fmt.Fprintf(stdout, "attackscout-agent %s\n", Version)
		return ExitOK
	case "help", "--help", "-h":
		_, _ = fmt.Fprint(stdout, usage)
		return ExitOK
	}
	_, _ = fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
	return ExitUsage
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func runScan(args []string, stdout, stderr io.Writer, e env) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var projects, certs multi
	root := fs.String("root", "", "")
	nginx := fs.String("nginx", "", "")
	apache := fs.String("apache", "", "")
	asJSON := fs.Bool("json", false, "")
	failOn := fs.String("fail-on", "none", "")
	lang := fs.String("lang", "en", "")
	online := fs.Bool("online", false, "")
	db := fs.String("db", "", "")
	fs.Var(&projects, "project", "")
	fs.Var(&certs, "cert", "")
	fs.Usage = func() { _, _ = fmt.Fprint(stderr, usage) }
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	threshold, err := scan.ParseSeverity(*failOn)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return ExitUsage
	}
	if !i18n.Valid(*lang) {
		_, _ = fmt.Fprintf(stderr, "unknown language %q (en, fr)\n", *lang)
		return ExitUsage
	}
	if *nginx == "" {
		*nginx = firstDir(e.nginx)
	}
	if *apache == "" {
		*apache = firstDir(e.apache)
	}
	if *root == "" {
		*root = detectRoot(*nginx, *apache, e)
	}
	dbDir := *db
	if dbDir == "" {
		dbDir = vulns.DefaultDir()
	}
	var m vulns.Matcher = vulns.Offline{Dir: dbDir}
	if *online {
		m = onlineMatcher()
	}
	o := scan.Options{Root: *root, Projects: projects, Nginx: *nginx, Apache: *apache, Certs: certs,
		Now: e.now(), Exec: e.exec, PHPHintDirs: e.phpDirs, Matcher: m, GOOS: e.goos}
	rep := scan.Run(context.Background(), o)
	if *asJSON {
		err = report.JSON(stdout, rep, Version, *lang)
	} else {
		err = report.Text(stdout, rep, Version, *lang)
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return ExitUsage
	}
	if threshold >= 0 {
		for _, f := range rep.Findings {
			if f.Severity >= threshold {
				return ExitFindings
			}
		}
	}
	return ExitOK
}

// onlineMatcher is one of the two paths allowed to use the network (--online).
func onlineMatcher() vulns.Matcher {
	return vulns.Online{BaseURL: osvAPI, Client: vulns.NewHTTPClient()}
}

// runDBUpdate is one of the two paths allowed to use the network (db update).
func runDBUpdate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("db update", flag.ContinueOnError)
	fs.SetOutput(stderr)
	db := fs.String("db", "", "")
	ecos := fs.String("ecosystems", strings.Join(inventory.Ecosystems, ","), "")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	dir := *db
	if dir == "" {
		dir = vulns.DefaultDir()
	}
	var list []string
	for _, e := range strings.Split(*ecos, ",") {
		if e = strings.TrimSpace(e); e != "" {
			list = append(list, e)
		}
	}
	res := vulns.Update(context.Background(), dir, archiveHost, vulns.NewHTTPClient(), list)
	keys := make([]string, 0, len(res))
	for k := range res {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	code := ExitOK
	for _, k := range keys {
		if res[k] != nil {
			_, _ = fmt.Fprintf(stderr, "%s: %v\n", k, res[k])
			code = ExitFindings
			continue
		}
		_, _ = fmt.Fprintf(stdout, "%s: %s\n", k, vulns.ArchivePath(dir, k))
	}
	return code
}

func firstDir(candidates []string) string {
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			return c
		}
	}
	return ""
}

// siteMarkers tell that a directory is a web root.
var siteMarkers = []string{"wp-config.php", "index.php", "index.html", "web.config", "composer.json", "package.json", "wp-includes"}

func looksLikeSite(dir string) bool {
	for _, m := range siteMarkers {
		if _, err := os.Stat(filepath.Join(dir, m)); err == nil {
			return true
		}
	}
	return false
}

// detectRoot picks the web root: from the server configuration, then the
// usual places, then the current directory.
func detectRoot(nginx, apache string, e env) string {
	w := scan.LoadWebConfig(nginx, apache, "")
	for _, r := range append(append([]string{}, w.Roots...), e.roots...) {
		if looksLikeSite(r) {
			return r
		}
	}
	if wd, err := e.getwd(); err == nil && looksLikeSite(wd) {
		return wd
	}
	return ""
}
