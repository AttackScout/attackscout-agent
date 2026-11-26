package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Network rule: no network call except "db update" and "--online".
//
//  1. Only internal/vulns may import a networking package.
//  2. The functions of internal/vulns that build a network client
//     (Online, Update, UpdateFeeds, NewHTTPClient) are used only by two functions of
//     internal/cli: onlineMatcher (--online) and runDBUpdate (db update).
//  3. No telemetry, no update check: no other file mentions an http(s) host
//     except documentation links in comments and the report link.
//
// The default path is also checked at run time by
// internal/cli.TestDefaultScanUsesNoNetwork, which replaces
// http.DefaultTransport with a guard that counts every request.

var networkImports = []string{"net", "net/http", "net/url", "net/rpc", "net/smtp", "net/mail", "crypto/tls", "google.golang.org/grpc", "osv.dev/bindings/go/osvdev"}

const vulnsPkg = "github.com/attackscout/attackscout-agent/internal/vulns"

func sources(t *testing.T) map[string]*ast.File {
	t.Helper()
	out := map[string]*ast.File{}
	fset := token.NewFileSet()
	err := filepath.WalkDir(".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".")) && p != "." {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, parser.ParseComments)
		if err != nil {
			return err
		}
		out[filepath.ToSlash(p)] = f
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) < 10 {
		t.Fatalf("only %d source files found", len(out))
	}
	return out
}

func TestOnlyVulnsImportsNetwork(t *testing.T) {
	for p, f := range sources(t) {
		for _, imp := range f.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			for _, n := range networkImports {
				if (path == n || strings.HasPrefix(path, n+"/")) && !strings.HasPrefix(p, "internal/vulns/") {
					t.Errorf("%s imports %s: only internal/vulns may use the network", p, path)
				}
			}
		}
	}
}

func TestNetworkPathsAreExplicit(t *testing.T) {
	allowed := map[string]bool{"onlineMatcher": true, "runDBUpdate": true}
	networked := map[string]bool{"Online": true, "Update": true, "UpdateFeeds": true, "NewHTTPClient": true}
	uses := 0
	for p, f := range sources(t) {
		alias := ""
		for _, imp := range f.Imports {
			if path, _ := strconv.Unquote(imp.Path.Value); path == vulnsPkg {
				alias = "vulns"
				if imp.Name != nil {
					alias = imp.Name.Name
				}
			}
		}
		if alias == "" {
			continue
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			name := "<package scope>"
			if ok {
				name = fn.Name.Name
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == alias && networked[sel.Sel.Name] {
					uses++
					if p != "internal/cli/cli.go" || !allowed[name] {
						t.Errorf("%s: %s uses vulns.%s; only onlineMatcher and runDBUpdate may", p, name, sel.Sel.Name)
					}
				}
				return true
			})
		}
	}
	if uses != 6 {
		t.Errorf("expected 6 uses of the network functions (Online, NewHTTPClient three times, Update, UpdateFeeds), got %d", uses)
	}
}

func TestNoHostsInCode(t *testing.T) {
	allowedHosts := []string{
		"https://attackscout.com/en?utm_source=attackscout-agent&utm_medium=cli&utm_campaign=report",
		"https://github.com/AttackScout/attackscout-agent",
		"https://json.schemastore.org/sarif-2.1.0.json", // SARIF schema identifier, never fetched
		"https://osv-vulnerabilities.storage.googleapis.com",
		"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
		"https://endoflife.date/api/v1/products",
	}
	for p, f := range sources(t) {
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, _ := strconv.Unquote(lit.Value)
			if !strings.Contains(s, "http://") && !strings.Contains(s, "https://") {
				return true
			}
			for _, a := range allowedHosts {
				if s == a {
					return true
				}
			}
			if strings.HasPrefix(p, "internal/eol/") || strings.HasPrefix(p, "internal/i18n/") {
				return true // links printed in advice, never fetched
			}
			if strings.Contains(s, "https://") && strings.Contains(s, "%s") {
				return true
			}
			t.Errorf("%s: unexpected URL literal %q", p, s)
			return true
		})
	}
}

func TestEOLTableEmbedded(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("internal", "eol", "eol.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "//go:embed data.json") {
		t.Fatal("the end-of-life table must be embedded with go:embed")
	}
}

func TestGoModDirectDependencies(t *testing.T) {
	data, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	direct := 0
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "github.com/") || strings.HasPrefix(line, "google.golang.org/") || strings.HasPrefix(line, "osv.dev/") {
			if !strings.Contains(line, "// indirect") {
				direct++
			}
		}
	}
	if direct == 0 || direct > 6 {
		t.Errorf("%d direct dependencies: keep the list short and reviewed (see NOTICE)", direct)
	}
}
