package vulns

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	osvpb "github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/attackscout/attackscout-agent/internal/inventory"
)

var ecoPrefix = map[string]string{"npm": "npm", "go": "Go", "packagist": "Packagist"}

// zips returns one OSV archive per ecosystem built from testdata.
func zips(t *testing.T) map[string][]byte {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("testdata", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	bufs := map[string]*bytes.Buffer{}
	ws := map[string]*zip.Writer{}
	for _, f := range files {
		eco := ecoPrefix[strings.SplitN(filepath.Base(f), "-", 2)[0]]
		if ws[eco] == nil {
			bufs[eco] = &bytes.Buffer{}
			ws[eco] = zip.NewWriter(bufs[eco])
		}
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		w, err := ws[eco].Create(filepath.Base(f))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	out := map[string][]byte{}
	for eco, w := range ws {
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		out[eco] = bufs[eco].Bytes()
	}
	return out
}

// writeDB stores the archives where the library expects them.
func writeDB(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for eco, data := range zips(t) {
		p := ArchivePath(dir, eco)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func comps() []inventory.Component {
	return []inventory.Component{
		{Kind: inventory.KindDependency, Name: "lodash", Version: "4.17.20", Ecosystem: "npm", Package: "lodash", Exact: true},
		{Kind: inventory.KindFramework, Name: "Next.js", Version: "13.5.0", Ecosystem: "npm", Package: "next", Exact: true},
		{Kind: inventory.KindFramework, Name: "React", Version: "18.2.0", Ecosystem: "npm", Package: "react", Exact: true},
		{Kind: inventory.KindDependency, Name: "guzzlehttp/guzzle", Version: "7.4.0", Ecosystem: "Packagist", Package: "guzzlehttp/guzzle", Exact: true},
		{Kind: inventory.KindTerraformProvider, Name: "hashicorp/aws", Version: "5.31.0", Ecosystem: "Go", Package: "github.com/hashicorp/terraform-provider-aws", Exact: true},
		{Kind: inventory.KindDependency, Name: "django", Version: "3.2.0", Ecosystem: "PyPI", Package: "django", Exact: true},
		{Kind: inventory.KindCMSPlugin, Name: "Hello Forms", Version: "2.3.1"},
		{Kind: inventory.KindDependency, Name: "example-evil", Version: "1.0.0", Ecosystem: "npm", Package: "example-evil", Exact: true},
	}
}

func ids(vs []Vuln) []string {
	var out []string
	for _, v := range vs {
		out = append(out, v.ID)
	}
	return out
}

func TestOfflineMatch(t *testing.T) {
	dir := writeDB(t)
	before := Refusals()
	r := Offline{Dir: dir}.Match(context.Background(), comps())
	if Refusals() != before {
		t.Fatalf("offline match tried the network %d times", Refusals()-before)
	}
	if r.Mode != "offline" {
		t.Fatalf("mode %q", r.Mode)
	}
	for _, eco := range []string{"npm", "Packagist", "Go"} {
		if !r.Checked[eco] {
			t.Errorf("%s not checked: %v", eco, r.Reasons)
		}
		if r.DBDates[eco].IsZero() {
			t.Errorf("%s: no database date", eco)
		}
	}
	if r.Checked["PyPI"] || r.Reasons["PyPI"] == "" {
		t.Errorf("PyPI must be reported as not checked: %v %v", r.Checked, r.Reasons)
	}
	lodash := r.Vulns[0]
	if len(lodash) != 1 || lodash[0].ID != "GHSA-35jh-r3h4-6jhm" {
		t.Fatalf("lodash: %v", ids(lodash))
	}
	v := lodash[0]
	if v.Score != 7.2 || v.Severity != "high" || v.Fixed != "4.17.21" || v.CVE() != "CVE-2021-23337" {
		t.Errorf("lodash vuln: %+v", v)
	}
	next := r.Vulns[1]
	if len(next) != 1 || next[0].Fixed != "13.5.7" || next[0].Severity != "medium" {
		t.Errorf("next: %+v", next)
	}
	if len(r.Vulns[2]) != 0 {
		t.Errorf("react should have no vuln: %v", ids(r.Vulns[2]))
	}
	g := r.Vulns[3]
	if len(g) != 1 || g[0].Severity != "medium" || g[0].Fixed != "7.4.5" || g[0].Vector != "" {
		t.Errorf("guzzle: %+v", g)
	}
	aws := r.Vulns[4]
	if len(aws) != 1 || aws[0].Score != 10 || aws[0].Severity != "critical" || aws[0].Fixed != "5.40.0" {
		t.Errorf("aws: %+v", aws)
	}
	if mal := r.Vulns[7]; len(mal) != 1 || mal[0].Severity != "critical" || mal[0].Fixed != "" {
		t.Errorf("malicious package: %+v", mal)
	}
	if len(r.Vulns[6]) != 0 {
		t.Error("a component without ecosystem cannot match")
	}
}

func TestOfflineNoDatabase(t *testing.T) {
	r := Offline{Dir: t.TempDir()}.Match(context.Background(), comps())
	if len(r.Checked) != 0 {
		t.Fatalf("nothing can be checked without a database: %v", r.Checked)
	}
	if r.Reasons["npm"] != "no local database" {
		t.Fatalf("reasons: %v", r.Reasons)
	}
}

func TestOfflineCorruptDatabase(t *testing.T) {
	dir := t.TempDir()
	p := ArchivePath(dir, "npm")
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("not a zip"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := Offline{Dir: dir}.Match(context.Background(), comps()[:1])
	if r.Checked["npm"] || r.Reasons["npm"] == "" {
		t.Fatalf("a corrupt archive must not count as checked: %v %v", r.Checked, r.Reasons)
	}
}

// osvAPI is a fake api.osv.dev that records what it receives.
type osvAPI struct {
	mu     sync.Mutex
	bodies []string
	paths  []string
	vulns  map[string]*osvpb.Vulnerability
	fail   bool
}

func (a *osvAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	a.mu.Lock()
	a.bodies = append(a.bodies, string(body))
	a.paths = append(a.paths, r.URL.Path)
	a.mu.Unlock()
	if a.fail {
		http.Error(w, "bad", http.StatusBadRequest)
		return
	}
	switch {
	case r.URL.Path == "/v1/querybatch":
		var q struct {
			Queries []struct {
				Package struct{ Name, Ecosystem string } `json:"package"`
				Version string                           `json:"version"`
			} `json:"queries"`
		}
		_ = json.Unmarshal(body, &q)
		type res struct {
			Vulns []map[string]string `json:"vulns,omitempty"`
		}
		out := struct {
			Results []res `json:"results"`
		}{}
		for _, qq := range q.Queries {
			var rr res
			for id, v := range a.vulns {
				if v.GetAffected()[0].GetPackage().GetName() == qq.Package.Name {
					rr.Vulns = append(rr.Vulns, map[string]string{"id": id, "modified": "2026-01-01T00:00:00Z"})
				}
			}
			out.Results = append(out.Results, rr)
		}
		_ = json.NewEncoder(w).Encode(out)
	case strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
		v := a.vulns[strings.TrimPrefix(r.URL.Path, "/v1/vulns/")]
		data, _ := protojson.Marshal(v)
		_, _ = w.Write(data)
	default:
		http.NotFound(w, r)
	}
}

func loadVuln(t *testing.T, name string) *osvpb.Vulnerability {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	v := &osvpb.Vulnerability{}
	if err := protojson.Unmarshal(data, v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestOnlineSendsOnlyPackages(t *testing.T) {
	api := &osvAPI{vulns: map[string]*osvpb.Vulnerability{"GHSA-35jh-r3h4-6jhm": loadVuln(t, "npm-lodash.json")}}
	srv := httptest.NewServer(api)
	defer srv.Close()
	cs := comps()
	cs[0].Source = "/var/www/secret-site.example.com/package-lock.json"
	r := Online{BaseURL: srv.URL, Client: srv.Client()}.Match(context.Background(), cs)
	if r.Mode != "online" || !r.Checked["npm"] || !r.Checked["Go"] {
		t.Fatalf("result: %+v", r)
	}
	if got := ids(r.Vulns[0]); len(got) != 1 || got[0] != "GHSA-35jh-r3h4-6jhm" {
		t.Fatalf("lodash: %v", got)
	}
	if r.Vulns[0][0].Fixed != "4.17.21" {
		t.Errorf("fixed: %q", r.Vulns[0][0].Fixed)
	}
	all := strings.Join(api.bodies, "\n")
	for _, leak := range []string{"secret-site", "example.com", "/var/www", "Hello Forms"} {
		if strings.Contains(all, leak) {
			t.Errorf("request leaked %q: %s", leak, all)
		}
	}
	for _, p := range api.paths {
		if p != "/v1/querybatch" && !strings.HasPrefix(p, "/v1/vulns/") {
			t.Errorf("unexpected endpoint %s", p)
		}
	}
	var q map[string]any
	if err := json.Unmarshal([]byte(api.bodies[0]), &q); err != nil {
		t.Fatal(err)
	}
	for _, item := range q["queries"].([]any) {
		for k := range item.(map[string]any) {
			if k != "package" && k != "version" {
				t.Errorf("unexpected query field %q", k)
			}
		}
	}
}

func TestOnlineFailure(t *testing.T) {
	srv := httptest.NewServer(&osvAPI{fail: true})
	defer srv.Close()
	r := Online{BaseURL: srv.URL, Client: srv.Client()}.Match(context.Background(), comps())
	if len(r.Checked) != 0 || r.Reasons["npm"] == "" {
		t.Fatalf("a failed query must leave ecosystems unchecked: %+v", r)
	}
	if empty := (Online{BaseURL: srv.URL, Client: srv.Client()}).Match(context.Background(), nil); len(empty.Reasons) != 0 {
		t.Fatal("no component, no query")
	}
}

func TestUpdate(t *testing.T) {
	archives := zips(t)
	var mu sync.Mutex
	var gets int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		eco := strings.Split(strings.Trim(r.URL.Path, "/"), "/")[0]
		data, ok := archives[eco]
		if !ok {
			http.NotFound(w, r)
			return
		}
		sum := make([]byte, 4)
		binary.BigEndian.PutUint32(sum, crc32.Checksum(data, crc32.MakeTable(crc32.Castagnoli)))
		w.Header().Set("X-Goog-Hash", "crc32c="+base64.StdEncoding.EncodeToString(sum))
		if r.Method == http.MethodGet {
			mu.Lock()
			gets++
			mu.Unlock()
			_, _ = w.Write(data)
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	res := Update(context.Background(), dir, srv.URL, srv.Client(), []string{"npm", "Go", "PyPI"})
	if res["npm"] != nil || res["Go"] != nil {
		t.Fatalf("update: %v", res)
	}
	if res["PyPI"] == nil {
		t.Fatal("a missing archive must be an error")
	}
	if _, err := os.Stat(ArchivePath(dir, "npm")); err != nil {
		t.Fatal(err)
	}
	// second run: same checksum, no new download
	res = Update(context.Background(), dir, srv.URL, srv.Client(), []string{"npm"})
	if res["npm"] != nil || gets != 2 {
		t.Fatalf("second update: %v, %d downloads", res, gets)
	}
	r := Offline{Dir: dir}.Match(context.Background(), comps()[:1])
	if len(r.Vulns[0]) != 1 {
		t.Fatalf("downloaded database not used: %+v", r)
	}
}

func TestCVSS3(t *testing.T) {
	cases := map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10,
		"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H": 7.2,
		"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N": 5.9,
		"CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N": 4.6,
		"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N": 1.6,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0,
	}
	for vec, want := range cases {
		got, ok := CVSS3(vec)
		if !ok || got != want {
			t.Errorf("%s: got %v %v, want %v", vec, got, ok, want)
		}
	}
	for _, bad := range []string{"", "CVSS:4.0/AV:N", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H", "CVSS:3.1/AV:N/AC:L/PR:X/UI:N/S:U/C:H/I:H/A:H"} {
		if _, ok := CVSS3(bad); ok {
			t.Errorf("%q must be rejected", bad)
		}
	}
	for s, want := range map[float64]string{9.1: "critical", 7: "high", 4: "medium", 3.9: "low"} {
		if got := ScoreSeverity(s); got != want {
			t.Errorf("%v: %s", s, got)
		}
	}
}

func TestConvert(t *testing.T) {
	c := inventory.Component{Name: "x", Version: "1.0.0", Ecosystem: "npm", Package: "x"}
	for sev, want := range map[string]string{"CRITICAL": "critical", "HIGH": "high", "LOW": "low", "MODERATE": "medium", "": "medium"} {
		v := &osvpb.Vulnerability{}
		raw := `{"id":"GHSA-test","database_specific":{"severity":"` + sev + `"},"affected":[{"package":{"name":"x","ecosystem":"npm"},"severity":[{"type":"CVSS_V3","score":"bad"}],"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"not-a-version"}]}]}]}`
		if err := protojson.Unmarshal([]byte(raw), v); err != nil {
			t.Fatal(err)
		}
		got := Convert(v, c)
		if got.Severity != want {
			t.Errorf("%s: %+v", sev, got)
		}
	}
	v := &osvpb.Vulnerability{}
	raw := `{"id":"OSV-1","affected":[{"package":{"name":"x","ecosystem":"npm"},"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"0.9.0"},{"fixed":"1.2.0"},{"fixed":"1.1.0"}]}]},{"package":{"name":"other","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"fixed":"1.0.1"}]}]}]}`
	if err := protojson.Unmarshal([]byte(raw), v); err != nil {
		t.Fatal(err)
	}
	got := Convert(v, c)
	if got.Score != 9.8 || got.Fixed != "1.1.0" || got.CVE() != "OSV-1" {
		t.Errorf("affected-level severity and smallest fix: %+v", got)
	}
	if (Vuln{ID: "CVE-2020-1"}).CVE() != "CVE-2020-1" {
		t.Error("a CVE identifier is its own CVE")
	}
}

func TestDefaults(t *testing.T) {
	if !strings.HasSuffix(DefaultDir(), "attackscout-agent") {
		t.Error(DefaultDir())
	}
	if NewHTTPClient().Timeout == 0 {
		t.Error("the network client needs a timeout")
	}
	f := factories{}
	if _, err := f.GoogleHTTPClient(context.Background()); err == nil {
		t.Error("no Google client")
	}
	if _, err := f.GRPCClientConn("x"); err == nil {
		t.Error("no gRPC")
	}
	if _, err := (refuse{}).RoundTrip(nil); err != ErrNetworkDisabled {
		t.Error(err)
	}
}
