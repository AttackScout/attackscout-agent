package scan

import (
	"crypto/dsa" //nolint:staticcheck // only to detect DSA keys, never to sign
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"time"

	"github.com/attackscout/attackscout-cli/internal/i18n"
)

// expiringDays: a certificate expiring sooner than this is reported.
const expiringDays = 30

// CheckCerts checks local PEM certificates: expiry, key size, signature.
func CheckCerts(paths []string, now time.Time) []Finding {
	var out []Finding
	for _, p := range paths {
		out = append(out, checkCertFile(p, now)...)
	}
	return out
}

func checkCertFile(path string, now time.Time) []Finding {
	data, err := readSmall(path)
	if err != nil {
		return []Finding{{ID: "cert-unreadable", Severity: Low, Path: path,
			Title: i18n.M("cert.unreadable"), Fix: i18n.M("fix.cert-unreadable")}}
	}
	var certs []*x509.Certificate
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue // private keys are skipped and never printed
		}
		if c, err := x509.ParseCertificate(b.Bytes); err == nil {
			certs = append(certs, c)
		}
	}
	if len(certs) == 0 {
		return []Finding{{ID: "cert-unreadable", Severity: Low, Path: path,
			Title: i18n.M("cert.nopem"), Fix: i18n.M("fix.cert-nopem")}}
	}
	var out []Finding
	for i, c := range certs {
		name := c.Subject.CommonName
		if name == "" && len(c.DNSNames) > 0 {
			name = c.DNSNames[0]
		}
		days := int(c.NotAfter.Sub(now).Hours() / 24)
		end := c.NotAfter.UTC().Format("2006-01-02")
		leaf := i == 0
		switch {
		case now.After(c.NotAfter) && leaf:
			out = append(out, Finding{ID: "cert-expired", Severity: Critical, Path: path,
				Title: i18n.M("cert.expired", name, end), Fix: i18n.M("fix.cert-expired")})
		case now.After(c.NotAfter):
			out = append(out, Finding{ID: "cert-chain-expired", Severity: High, Path: path,
				Title: i18n.M("cert.chain-expired", name, end), Fix: i18n.M("fix.cert-chain-expired")})
		case days < expiringDays && leaf:
			out = append(out, Finding{ID: "cert-expiring", Severity: High, Path: path,
				Title: i18n.M("cert.expiring", name, end, days), Fix: i18n.M("fix.cert-expiring")})
		case leaf:
			out = append(out, Finding{ID: "cert-valid", Severity: Info, Path: path,
				Title: i18n.M("cert.valid", name, end, days)})
		}
		if bits, weak := keyStrength(c); weak {
			out = append(out, Finding{ID: "cert-weak-key", Severity: High, Path: path,
				Title: i18n.M("cert.weak-key", name, c.PublicKeyAlgorithm.String(), bits), Fix: i18n.M("fix.cert-weak-key")})
		}
		switch c.SignatureAlgorithm {
		case x509.MD5WithRSA, x509.SHA1WithRSA, x509.ECDSAWithSHA1, x509.DSAWithSHA1:
			if !c.IsCA || leaf {
				out = append(out, Finding{ID: "cert-weak-signature", Severity: Medium, Path: path,
					Title: i18n.M("cert.weak-sig", name, c.SignatureAlgorithm.String()), Fix: i18n.M("fix.cert-weak-signature")})
			}
		}
	}
	return out
}

// keyStrength returns the key size and whether it is too weak.
func keyStrength(c *x509.Certificate) (int, bool) {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen(), k.N.BitLen() < 2048
	case *ecdsa.PublicKey:
		return k.Params().BitSize, k.Params().BitSize < 256
	case *dsa.PublicKey:
		return k.P.BitLen(), true
	}
	return 0, false
}
