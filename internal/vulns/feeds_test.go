package vulns

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const kevJSON = `{"vulnerabilities":[{"cveID":"CVE-2021-44228","dateAdded":"2021-12-10","dueDate":"2021-12-24","knownRansomwareCampaignUse":"Known"},{"cveID":""}]}`

func TestKEV(t *testing.T) {
	k, err := ParseKEV([]byte(kevJSON))
	if err != nil || len(k) != 1 {
		t.Fatalf("%v %v", k, err)
	}
	if _, err := ParseKEV([]byte("[")); err == nil {
		t.Error("bad JSON")
	}
	if e, ok := k.Lookup(Vuln{ID: "GHSA-jfh8-c2jp-5v3q", Aliases: []string{"CVE-2021-44228"}}); !ok || e.DateAdded != "2021-12-10" {
		t.Error("alias lookup")
	}
	if _, ok := k.Lookup(Vuln{ID: "CVE-2021-44228"}); !ok {
		t.Error("ID lookup")
	}
	if _, ok := k.Lookup(Vuln{ID: "CVE-1"}); ok {
		t.Error("unknown CVE")
	}
	if _, ok := KEV(nil).Lookup(Vuln{ID: "CVE-2021-44228"}); ok {
		t.Error("nil list")
	}
	dir := t.TempDir()
	if LoadKEV(dir) != nil {
		t.Error("absent list")
	}
	_ = os.MkdirAll(filepath.Dir(KEVPath(dir)), 0o750)
	_ = os.WriteFile(KEVPath(dir), []byte("x"), 0o600)
	if LoadKEV(dir) != nil {
		t.Error("corrupt list")
	}
	_ = os.WriteFile(KEVPath(dir), []byte(kevJSON), 0o600)
	if len(LoadKEV(dir)) != 1 {
		t.Error("list not loaded")
	}
	if !strings.HasSuffix(AdvisoryURL("GHSA-x"), "/vulnerability/GHSA-x") {
		t.Error(AdvisoryURL("GHSA-x"))
	}
}

func TestUpdateFeeds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/kev.json":
			_, _ = w.Write([]byte(kevJSON))
		case "/eol/apache-http-server/":
			_, _ = w.Write([]byte(`{"result":{"releases":[{"name":"2.4"}]}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	pathOf := func(d, p string) string { return filepath.Join(d, "eol", p+".json") }
	res := UpdateFeeds(context.Background(), dir, srv.URL+"/kev.json", srv.URL+"/eol/", srv.Client(),
		map[string]string{"apache": "apache-http-server", "nope": "nope"}, pathOf)
	if res["CISA KEV"] != nil || res["endoflife.date apache"] != nil || res["endoflife.date nope"] == nil {
		t.Fatalf("%v", res)
	}
	if _, err := os.Stat(pathOf(dir, "apache")); err != nil {
		t.Fatal(err)
	}
	if res = UpdateFeeds(context.Background(), dir, srv.URL+"/missing", srv.URL, srv.Client(), nil, pathOf); res["CISA KEV"] == nil {
		t.Error("404 KEV accepted")
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("<html>")) }))
	defer bad.Close()
	if res = UpdateFeeds(context.Background(), dir, bad.URL, bad.URL, bad.Client(), nil, pathOf); res["CISA KEV"] == nil {
		t.Error("non-JSON KEV accepted")
	}
}
