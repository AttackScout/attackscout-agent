//go:build windows

package scan

import (
	"os"
	"path/filepath"
	"testing"
)

// Windows paths: drive letters, backslashes and relative paths in the
// configuration are resolved with filepath.
func TestWindowsPaths(t *testing.T) {
	got := resolve(`C:\nginx\conf`, reNginxCert, "ssl_certificate certs/site.pem;\n"+`ssl_certificate C:\certs\abs.pem;`+"\n")
	if len(got) != 2 || got[0] != `C:\nginx\conf\certs\site.pem` || got[1] != `C:\certs\abs.pem` {
		t.Fatalf("%v", got)
	}
	root := t.TempDir()
	web := filepath.Join(root, "wwwroot")
	if err := os.MkdirAll(web, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "wp-config.php"), []byte("<?php"), 0o600); err != nil {
		t.Fatal(err)
	}
	if p := FindWPConfig(web + `\`); p != filepath.Join(root, "wp-config.php") {
		t.Fatalf("parent wp-config with a trailing backslash: %q", p)
	}
	if err := os.WriteFile(filepath.Join(web, "backup.zip"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	fs := CheckSensitive(web)
	if len(fs) != 1 || fs[0].Path != filepath.Join(web, "backup.zip") {
		t.Fatalf("%+v", fs)
	}
	if fs[0].Title.Render("en") != "Sensitive backup or archive in the web root: backup.zip (content not read)" {
		t.Error(fs[0].Title.Render("en"))
	}
}
