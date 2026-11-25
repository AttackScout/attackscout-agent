package eol

import (
	"testing"
	"time"
)

var now = time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC)

func TestDefaultTable(t *testing.T) {
	tb := Default()
	if tb.Updated != "2026-11-25" {
		t.Fatalf("table date: %s", tb.Updated)
	}
	for _, p := range []string{"php", "wordpress", "drupal", "joomla", "prestashop", "nodejs", "dotnet", "react", "nextjs"} {
		if len(tb.Products[p].Cycles) == 0 || tb.Products[p].Link == "" {
			t.Errorf("%s missing", p)
		}
		for _, c := range tb.Products[p].Cycles {
			if c.EOL != "" {
				if _, err := time.Parse("2006-01-02", c.EOL); err != nil {
					t.Errorf("%s %s: %v", p, c.Cycle, err)
				}
			}
		}
	}
}

func TestLookup(t *testing.T) {
	tb := Default()
	cases := []struct {
		product, version   string
		known, eol, behind bool
		cycle              string
	}{
		{"php", "8.1.2", true, true, true, "8.1"},
		{"php", "8.3.36", true, false, false, "8.3"},
		{"php", "5.6.40", true, true, false, "5"},
		{"php", "9.0.0", false, false, false, ""},
		{"drupal", "7.98", true, true, true, "7"},
		{"drupal", "10.6.1", true, false, true, "10.6"},
		{"wordpress", "6.4.2", true, false, true, "6.4"},
		{"prestashop", "1.6.1.24", true, true, false, "1.6"},
		{"nextjs", "13.5.0", true, true, false, "13"},
		{"react", "18.2.0", true, false, false, "18"},
		{"nodejs", "20.11.1", true, true, false, "20"},
		{"dotnet", "6.0", true, true, false, "6"},
		{"unknown", "1.0", false, false, false, ""},
		{"php", "abc", false, false, false, ""},
	}
	for _, c := range cases {
		st := tb.Lookup(c.product, c.version, now)
		if st.Known != c.known || st.EOL != c.eol || st.Behind != c.behind || st.Cycle != c.cycle {
			t.Errorf("%s %s: %+v", c.product, c.version, st)
		}
	}
	st := tb.Lookup("php", "8.2.1", now)
	if st.EOL || st.EOLDate == nil || st.DaysLeft != 36 {
		t.Errorf("8.2 soon: %+v", st)
	}
	if st := tb.Lookup("drupal", "10.6.21", now); st.EOLDate.Format("2006-01-02") != "2026-12-09" {
		t.Errorf("vendor date for Drupal 10: %v", st.EOLDate)
	}
}

func TestParseErrors(t *testing.T) {
	if _, err := Parse([]byte("{")); err == nil {
		t.Error("bad JSON accepted")
	}
	if _, err := Parse([]byte(`{"updated":""}`)); err == nil {
		t.Error("empty table accepted")
	}
}

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.3", 0}, {"1.2", "1.2.0", 0}, {"1.2.3", "1.10.0", -1},
		{"2.0", "1.9.9", 1}, {"8.1.2-1ubuntu", "8.1.2", 0}, {"1.2.3.4", "1.2.3", 1},
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("%s vs %s: %d", c.a, c.b, got)
		}
	}
}
