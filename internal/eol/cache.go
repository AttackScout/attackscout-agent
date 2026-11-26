package eol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Slugs maps the products of the table to their endoflife.date name.
var Slugs = map[string]string{
	"php": "php", "wordpress": "wordpress", "drupal": "drupal", "joomla": "joomla", "prestashop": "prestashop",
	"nodejs": "nodejs", "dotnet": "dotnet", "react": "react", "nextjs": "nextjs",
	"nginx": "nginx", "apache": "apache-http-server", "iis": "iis",
}

// CachePath is where "db update" stores the endoflife.date data of a product.
func CachePath(dir, product string) string {
	return filepath.Join(dir, "endoflife", product+".json")
}

// apiProduct is the endoflife.date API v1 answer for one product.
type apiProduct struct {
	Result struct {
		Releases []struct {
			Name    string `json:"name"`
			IsEOL   bool   `json:"isEol"`
			EOLFrom string `json:"eolFrom"`
			Latest  *struct {
				Name string `json:"name"`
			} `json:"latest"`
		} `json:"releases"`
	} `json:"result"`
}

// ParseAPI turns an endoflife.date API v1 answer into branches.
func ParseAPI(data []byte) ([]Cycle, error) {
	var a apiProduct
	if err := json.Unmarshal(data, &a); err != nil {
		return nil, err
	}
	var out []Cycle
	for _, r := range a.Result.Releases {
		if r.Name == "" {
			continue
		}
		c := Cycle{Cycle: r.Name, EOL: r.EOLFrom, Ended: r.IsEOL}
		if r.Latest != nil {
			c.Latest = r.Latest.Name
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, os.ErrInvalid
	}
	return out, nil
}

// Load returns the embedded table, with the branches of every product
// replaced by the data downloaded by "db update" in dir, when present. The
// table date becomes the oldest download date. Nothing is fetched here.
func Load(dir string) *Table {
	t := Default()
	if dir == "" {
		return t
	}
	var oldest time.Time
	for product := range Slugs {
		p, ok := t.Products[product]
		path := CachePath(dir, product)
		data, err := os.ReadFile(path)
		if err != nil || !ok {
			continue
		}
		cycles, err := ParseAPI(data)
		if err != nil {
			continue
		}
		p.Cycles = cycles
		t.Products[product] = p
		if st, err := os.Stat(path); err == nil && (oldest.IsZero() || st.ModTime().Before(oldest)) {
			oldest = st.ModTime()
		}
	}
	if !oldest.IsZero() {
		t.Updated = oldest.UTC().Format("2006-01-02")
		t.Source = "endoflife.date (MIT), downloaded by db update"
	}
	return t
}
