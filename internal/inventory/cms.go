package inventory

import (
	"bufio"
	"encoding/xml"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type cmsProbe struct {
	product, label, file, pkg string
	re                        *regexp.Regexp
}

var cmsProbes = []cmsProbe{
	{"wordpress", "WordPress", "wp-includes/version.php", "", regexp.MustCompile(`\$wp_version\s*=\s*'([^']+)'`)},
	{"drupal", "Drupal", "core/lib/Drupal.php", "drupal/core", regexp.MustCompile(`const\s+VERSION\s*=\s*'([^']+)'`)},
	{"drupal", "Drupal", "includes/bootstrap.inc", "", regexp.MustCompile(`define\('VERSION',\s*'([^']+)'\)`)},
	{"joomla", "Joomla", "administrator/manifests/files/joomla.xml", "joomla/joomla-cms", regexp.MustCompile(`<version>([^<]+)</version>`)},
	{"prestashop", "PrestaShop", "app/AppKernel.php", "prestashop/prestashop", regexp.MustCompile(`const\s+VERSION\s*=\s*'([^']+)'`)},
	{"prestashop", "PrestaShop", "config/settings.inc.php", "prestashop/prestashop", regexp.MustCompile(`define\('_PS_VERSION_',\s*'([^']+)'\)`)},
}

// CMS detects WordPress, Drupal, Joomla and PrestaShop with their plugins,
// modules, extensions and themes.
func CMS(root string) []Component {
	var out []Component
	found := map[string]bool{}
	for _, p := range cmsProbes {
		if found[p.product] {
			continue
		}
		path := filepath.Join(root, filepath.FromSlash(p.file))
		data, err := readSmall(path)
		if err != nil {
			continue
		}
		m := p.re.FindSubmatch(data)
		if m == nil {
			continue
		}
		found[p.product] = true
		c := Component{Kind: KindCMS, Product: p.product, Name: p.label, Version: string(m[1]), Source: path, Exact: true}
		if p.pkg != "" {
			c.Ecosystem, c.Package = EcoPackagist, p.pkg
		}
		out = append(out, c)
	}
	if found["wordpress"] {
		out = append(out, wordpressExtras(root)...)
	}
	if found["drupal"] {
		out = append(out, drupalExtras(root)...)
	}
	if found["joomla"] {
		out = append(out, joomlaExtras(root)...)
	}
	return out
}

var reHeader = regexp.MustCompile(`(?im)^[\s*#@/]*(Plugin Name|Theme Name|Version):\s*(.+?)\s*$`)

// header reads "Name: value" lines in the first 8 KB of a file.
func header(path string) map[string]string {
	out := map[string]string{}
	fh, err := os.Open(path)
	if err != nil {
		return out
	}
	defer func() { _ = fh.Close() }()
	buf := make([]byte, 8192)
	n, _ := bufio.NewReader(fh).Read(buf)
	for _, m := range reHeader.FindAllSubmatch(buf[:n], -1) {
		k := strings.ToLower(string(m[1]))
		if _, ok := out[k]; !ok {
			out[k] = string(m[2])
		}
	}
	return out
}

func wordpressExtras(root string) []Component {
	var out []Component
	plugins := filepath.Join(root, "wp-content", "plugins")
	entries, _ := os.ReadDir(plugins)
	for _, e := range entries {
		var files []string
		if e.IsDir() {
			files, _ = filepath.Glob(filepath.Join(plugins, e.Name(), "*.php"))
		} else if strings.HasSuffix(e.Name(), ".php") {
			files = []string{filepath.Join(plugins, e.Name())}
		}
		for _, f := range files {
			h := header(f)
			if h["plugin name"] == "" {
				continue
			}
			out = append(out, Component{Kind: KindCMSPlugin, Name: h["plugin name"], Version: h["version"], Source: f, Exact: h["version"] != ""})
			break
		}
	}
	themes := filepath.Join(root, "wp-content", "themes")
	entries, _ = os.ReadDir(themes)
	for _, e := range entries {
		f := filepath.Join(themes, e.Name(), "style.css")
		h := header(f)
		if e.IsDir() && h["theme name"] != "" {
			out = append(out, Component{Kind: KindCMSTheme, Name: h["theme name"], Version: h["version"], Source: f, Exact: h["version"] != ""})
		}
	}
	return out
}

var (
	reInfoVersion = regexp.MustCompile(`(?m)^version:\s*['"]?([^'"\s]+)['"]?`)
	reInfoName    = regexp.MustCompile(`(?m)^name:\s*['"]?([^'"\n]+?)['"]?\s*$`)
	reDrupalCore  = regexp.MustCompile(`^\d+\.x-(.+)$`)
)

// drupalVersion turns "8.x-1.5" into the Composer version "1.5.0".
func drupalVersion(v string) string {
	if m := reDrupalCore.FindStringSubmatch(v); m != nil {
		v = m[1]
	}
	rel, suffix, _ := strings.Cut(v, "-")
	if strings.Count(rel, ".") == 1 {
		rel += ".0"
	}
	if suffix != "" {
		return rel + "-" + suffix
	}
	return rel
}

func drupalExtras(root string) []Component {
	var out []Component
	for _, sub := range []struct{ dir, kind string }{
		{"modules", KindCMSModule}, {"themes", KindCMSTheme},
		{filepath.Join("web", "modules"), KindCMSModule}, {filepath.Join("web", "themes"), KindCMSTheme},
	} {
		base := filepath.Join(root, sub.dir)
		for _, pattern := range []string{filepath.Join(base, "*", "*.info.yml"), filepath.Join(base, "contrib", "*", "*.info.yml")} {
			files, _ := filepath.Glob(pattern)
			for _, f := range files {
				data, err := readSmall(f)
				if err != nil {
					continue
				}
				m := reInfoVersion.FindSubmatch(data)
				if m == nil || strings.Contains(string(m[1]), "VERSION") {
					continue // custom code without a release
				}
				machine := strings.TrimSuffix(filepath.Base(f), ".info.yml")
				name := machine
				if n := reInfoName.FindSubmatch(data); n != nil {
					name = string(n[1])
				}
				out = append(out, Component{Kind: sub.kind, Name: name, Version: drupalVersion(string(m[1])),
					Ecosystem: EcoPackagist, Package: "drupal/" + machine, Source: f, Exact: true})
			}
		}
	}
	return out
}

type joomlaManifest struct {
	XMLName xml.Name
	Type    string `xml:"type,attr"`
	Name    string `xml:"name"`
	Version string `xml:"version"`
}

func joomlaExtras(root string) []Component {
	var out []Component
	patterns := []struct{ glob, kind string }{
		{"administrator/components/*/*.xml", KindCMSExtension},
		{"components/*/*.xml", KindCMSExtension},
		{"modules/*/*.xml", KindCMSExtension},
		{"administrator/modules/*/*.xml", KindCMSExtension},
		{"plugins/*/*/*.xml", KindCMSExtension},
		{"templates/*/templateDetails.xml", KindCMSTheme},
		{"administrator/templates/*/templateDetails.xml", KindCMSTheme},
	}
	seen := map[string]bool{}
	for _, p := range patterns {
		files, _ := filepath.Glob(filepath.Join(root, filepath.FromSlash(p.glob)))
		for _, f := range files {
			data, err := readSmall(f)
			if err != nil {
				continue
			}
			var m joomlaManifest
			if xml.Unmarshal(data, &m) != nil || m.XMLName.Local != "extension" || m.Name == "" || m.Version == "" {
				continue
			}
			k := m.Name + "\x00" + m.Version
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, Component{Kind: p.kind, Name: strings.TrimSpace(m.Name), Version: strings.TrimSpace(m.Version), Source: f, Exact: true})
		}
	}
	return out
}
