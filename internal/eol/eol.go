// Package eol holds the end-of-life tables embedded in the binary.
// Nothing is downloaded: the data ships with the release and carries its date.
package eol

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

//go:embed data.json
var embedded []byte

// Cycle is one release branch of a product.
type Cycle struct {
	Cycle  string `json:"cycle"`
	EOL    string `json:"eol,omitempty"`
	Ended  bool   `json:"ended,omitempty"`
	Latest string `json:"latest,omitempty"`
}

// Product is a product and its branches.
type Product struct {
	Label  string  `json:"label"`
	Link   string  `json:"link"`
	Cycles []Cycle `json:"cycles"`
}

// Table is the full embedded data set.
type Table struct {
	Updated  string             `json:"updated"`
	Source   string             `json:"source"`
	Products map[string]Product `json:"products"`
}

// Status is the lifecycle state of one version.
type Status struct {
	Product  string
	Label    string
	Link     string
	Version  string
	Cycle    string
	Known    bool       // a branch matched
	EOL      bool       // branch is past its end of life
	EOLDate  *time.Time // nil when unknown
	DaysLeft int        // days until end of life, when EOLDate is set and not reached
	Latest   string     // latest patch of the branch, may be empty
	Behind   bool       // version is older than Latest
}

// Parse decodes a table.
func Parse(data []byte) (*Table, error) {
	var t Table
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("eol table: %w", err)
	}
	if t.Updated == "" || len(t.Products) == 0 {
		return nil, fmt.Errorf("eol table: missing date or products")
	}
	return &t, nil
}

// Default returns the table embedded in the binary.
func Default() *Table {
	t, err := Parse(embedded)
	if err != nil {
		panic(err) // covered by tests: the embedded file is always valid
	}
	return t
}

// Lookup finds the branch of version for product and computes its status at now.
func (t *Table) Lookup(product, version string, now time.Time) Status {
	st := Status{Product: product, Version: version}
	p, ok := t.Products[product]
	if !ok {
		return st
	}
	st.Label, st.Link = p.Label, p.Link
	vparts := parts(version)
	best := -1
	for i, c := range p.Cycles {
		cp := parts(c.Cycle)
		if !prefix(cp, vparts) {
			continue
		}
		if best < 0 || len(cp) > len(parts(p.Cycles[best].Cycle)) {
			best = i
		}
	}
	if best < 0 {
		return st
	}
	c := p.Cycles[best]
	st.Known, st.Cycle, st.Latest = true, c.Cycle, c.Latest
	st.EOL = c.Ended
	if d, err := time.Parse("2006-01-02", c.EOL); err == nil {
		st.EOLDate = &d
		if !now.Before(d) {
			st.EOL = true
		} else {
			st.DaysLeft = int(d.Sub(now).Hours() / 24)
		}
	}
	if c.Latest != "" && Compare(version, c.Latest) < 0 {
		st.Behind = true
	}
	return st
}

// parts splits "8.1.2-1ubuntu" into [8 1 2].
func parts(v string) []int {
	var out []int
	for _, s := range strings.Split(v, ".") {
		n := 0
		digits := 0
		for _, r := range s {
			if r < '0' || r > '9' {
				break
			}
			digits++
		}
		if digits == 0 {
			break
		}
		n, _ = strconv.Atoi(s[:digits])
		out = append(out, n)
		if digits < len(s) {
			break
		}
	}
	return out
}

func prefix(p, v []int) bool {
	if len(p) == 0 || len(p) > len(v) {
		return false
	}
	for i := range p {
		if p[i] != v[i] {
			return false
		}
	}
	return true
}

// Compare compares two dotted versions numerically: -1, 0 or 1.
func Compare(a, b string) int {
	pa, pb := parts(a), parts(b)
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}
