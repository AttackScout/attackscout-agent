package eol

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

const apiPHP = `{"schema_version":"1.2.0","result":{"name":"php","releases":[
{"name":"8.4","isEol":false,"eolFrom":"2028-12-31","latest":{"name":"8.4.99"}},
{"name":"7.4","isEol":true,"eolFrom":"2022-11-28","latest":null},
{"name":""}]}}`

func TestParseAPI(t *testing.T) {
	cs, err := ParseAPI([]byte(apiPHP))
	if err != nil || len(cs) != 2 || cs[0].Latest != "8.4.99" || !cs[1].Ended || cs[1].Latest != "" {
		t.Fatalf("%+v %v", cs, err)
	}
	if _, err := ParseAPI([]byte("{")); err == nil {
		t.Error("bad JSON")
	}
	if _, err := ParseAPI([]byte(`{"result":{"releases":[]}}`)); err == nil {
		t.Error("empty product")
	}
}

func TestLoadCache(t *testing.T) {
	if Load("").Updated != Default().Updated {
		t.Error("no directory: embedded table")
	}
	dir := t.TempDir()
	if Load(dir).Updated != Default().Updated {
		t.Error("empty cache: embedded table")
	}
	p := CachePath(dir, "php")
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(apiPHP), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(CachePath(dir, "nginx"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	when := time.Date(2027, 1, 2, 0, 0, 0, 0, time.UTC)
	_ = os.Chtimes(p, when, when)
	tb := Load(dir)
	if tb.Updated != "2027-01-02" {
		t.Error(tb.Updated)
	}
	st := tb.Lookup("php", "8.4.1", when)
	if !st.Known || st.Latest != "8.4.99" || !st.Behind {
		t.Errorf("%+v", st)
	}
	if len(tb.Products["nginx"].Cycles) != len(Default().Products["nginx"].Cycles) {
		t.Error("a corrupt file must keep the embedded data")
	}
	for _, p := range []string{"nginx", "apache", "iis"} {
		if _, ok := Default().Products[p]; !ok {
			t.Errorf("%s missing from the embedded table", p)
		}
		if Slugs[p] == "" {
			t.Errorf("%s has no endoflife.date name", p)
		}
	}
	if !Default().Lookup("apache", "2.2.34", when).EOL || !Default().Lookup("nginx", "1.18.0", when).EOL {
		t.Error("old web servers must be past their end of life")
	}
}
