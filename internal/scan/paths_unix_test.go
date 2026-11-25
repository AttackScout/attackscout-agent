//go:build !windows

package scan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUnixPaths(t *testing.T) {
	got := resolve("/etc/nginx", reNginxCert, "ssl_certificate certs/site.pem;\nssl_certificate /etc/ssl/abs.pem;\n")
	if len(got) != 2 || got[0] != "/etc/nginx/certs/site.pem" || got[1] != "/etc/ssl/abs.pem" {
		t.Fatalf("%v", got)
	}
}

// TestPermsReal checks real Unix permission bits (Linux and macOS).
func TestPermsReal(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]os.FileMode{"index.php": 0o666, "wp-config.php": 0o644, "ok.php": 0o640}
	for name, mode := range files {
		p := filepath.Join(root, name)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}
	up := filepath.Join(root, "uploads")
	if err := os.Mkdir(up, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(up, 0o777); err != nil {
		t.Fatal(err)
	}
	got := byID(CheckPerms(root))
	if len(got["perm-file-world-writable"]) != 1 || len(got["perm-dir-777"]) != 1 || len(got["perm-secret-world-readable"]) != 1 {
		t.Fatalf("%v", got)
	}
	// nothing was changed
	st, err := os.Stat(filepath.Join(root, "index.php"))
	if err != nil || st.Mode().Perm() != 0o666 {
		t.Fatal("the scan must not change permissions")
	}
}
