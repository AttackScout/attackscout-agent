package vulns

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Remote feeds downloaded by "db update" only.
const (
	DefaultKEVURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	DefaultEOLBase = "https://endoflife.date/api/v1/products"
)

// maxFeed caps one download (the full Debian archive is about 300 MB).
const maxFeed = 2 << 30

// KEVPath is where the CISA Known Exploited Vulnerabilities list is kept.
func KEVPath(dir string) string {
	return filepath.Join(dir, "kev", "known_exploited_vulnerabilities.json")
}

// KEVEntry is one vulnerability exploited in the wild, according to CISA.
type KEVEntry struct {
	CVE        string `json:"cveID"`
	DateAdded  string `json:"dateAdded"`
	DueDate    string `json:"dueDate"`
	Ransomware string `json:"knownRansomwareCampaignUse"`
}

// KEV is the CISA list indexed by CVE identifier.
type KEV map[string]KEVEntry

// ParseKEV reads the CISA JSON feed.
func ParseKEV(data []byte) (KEV, error) {
	var f struct {
		Vulnerabilities []KEVEntry `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("kev: %w", err)
	}
	out := KEV{}
	for _, v := range f.Vulnerabilities {
		if v.CVE != "" {
			out[v.CVE] = v
		}
	}
	return out, nil
}

// LoadKEV reads the list downloaded by "db update"; nil when absent.
func LoadKEV(dir string) KEV {
	data, err := os.ReadFile(KEVPath(dir))
	if err != nil {
		return nil
	}
	k, err := ParseKEV(data)
	if err != nil {
		return nil
	}
	return k
}

// Lookup returns the KEV entry of a vulnerability, by its ID or aliases.
func (k KEV) Lookup(v Vuln) (KEVEntry, bool) {
	if k == nil {
		return KEVEntry{}, false
	}
	if e, ok := k[v.ID]; ok {
		return e, true
	}
	for _, a := range v.Aliases {
		if e, ok := k[a]; ok {
			return e, true
		}
	}
	return KEVEntry{}, false
}

// download writes url to path through a temporary file.
func download(ctx context.Context, c *http.Client, u, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", u, resp.StatusCode)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".download-*")
	if err != nil {
		return err
	}
	_, err = io.Copy(tmp, io.LimitReader(resp.Body, maxFeed))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// UpdateFeeds downloads the CISA KEV list and the endoflife.date data of
// each product (product key → endoflife.date name) into dir. It is called
// by "db update" only. pathOf gives the cache file of a product.
func UpdateFeeds(ctx context.Context, dir, kevURL, eolBase string, c *http.Client, products map[string]string, pathOf func(dir, product string) string) map[string]error {
	out := map[string]error{}
	err := download(ctx, c, kevURL, KEVPath(dir))
	if err == nil {
		var data []byte
		if data, err = os.ReadFile(KEVPath(dir)); err == nil {
			_, err = ParseKEV(data)
		}
	}
	out["CISA KEV"] = err
	for product, slug := range products {
		u := strings.TrimSuffix(eolBase, "/") + "/" + url.PathEscape(slug) + "/"
		out["endoflife.date "+product] = download(ctx, c, u, pathOf(dir, product))
	}
	return out
}
