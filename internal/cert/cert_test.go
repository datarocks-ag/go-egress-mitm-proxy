package cert

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/elazarl/goproxy"
	gopkcs12 "software.sslmate.com/src/go-pkcs12"
)

// generateTestCert creates a self-signed CA certificate valid for the given duration.
func generateTestCert(t *testing.T, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test Org"},
		},
		Issuer: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return tlsCert
}

// captureLogs runs fn and returns the captured slog JSON output.
func captureLogs(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	old := slog.Default()
	slog.SetDefault(logger)
	defer slog.SetDefault(old)
	fn()
	return buf.String()
}

// writeTestCAPEM generates a CA certificate and key as PEM files in dir.
func writeTestCAPEM(t *testing.T, dir, cn, org string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{org},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	err = os.WriteFile(filepath.Join(dir, "ca.crt"), certPEM, 0o600)
	if err != nil {
		t.Fatalf("write cert: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	err = os.WriteFile(filepath.Join(dir, "ca.key"), keyPEM, 0o600)
	if err != nil {
		t.Fatalf("write key: %v", err)
	}
}

func generateTestP12(t *testing.T, dir, cn, org, password string) (certPath, p12Path string) {
	t.Helper()
	keyPath := filepath.Join(dir, "ca.key")
	certPath = filepath.Join(dir, "ca.crt")
	p12Path = filepath.Join(dir, "truststore.p12")

	ctx := context.Background()

	//nolint:gosec // test helper: all arguments are test-controlled constants
	cmd := exec.CommandContext(ctx, "openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", keyPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("openssl genkey: %v\n%s", err, out)
	}

	//nolint:gosec // test helper: all arguments are test-controlled constants
	cmd = exec.CommandContext(ctx, "openssl", "req", "-new", "-x509", "-key", keyPath,
		"-out", certPath, "-days", "1", "-subj", "/CN="+cn+"/O="+org)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("openssl req: %v\n%s", err, out)
	}

	//nolint:gosec // test helper: all arguments are test-controlled constants
	cmd = exec.CommandContext(ctx, "openssl", "pkcs12", "-export",
		"-in", certPath, "-inkey", keyPath,
		"-out", p12Path, "-passout", "pass:"+password,
		"-certpbe", "PBE-SHA1-3DES", "-keypbe", "PBE-SHA1-3DES", "-macalg", "SHA1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("openssl pkcs12: %v\n%s", err, out)
	}

	return certPath, p12Path
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestLogMITMCertInfo(t *testing.T) {
	// Save and restore global state
	origCa := goproxy.GoproxyCa
	defer func() { goproxy.GoproxyCa = origCa }()

	t.Run("valid long-lived cert", func(t *testing.T) {
		goproxy.GoproxyCa = generateTestCert(t,
			time.Now().Add(-24*time.Hour),
			time.Now().Add(365*24*time.Hour),
		)
		output := captureLogs(t, LogMITMCertInfo)

		if !contains(output, "MITM CA certificate loaded") {
			t.Error("expected 'MITM CA certificate loaded' log line")
		}
		if !contains(output, "Test CA") {
			t.Error("expected subject/issuer to contain 'Test CA'")
		}
		if !contains(output, `"is_ca":true`) {
			t.Error("expected is_ca to be true")
		}
		if contains(output, "EXPIRED") || contains(output, "expires soon") {
			t.Error("should not warn about expiry for long-lived cert")
		}
	})

	t.Run("expired cert", func(t *testing.T) {
		goproxy.GoproxyCa = generateTestCert(t,
			time.Now().Add(-48*time.Hour),
			time.Now().Add(-1*time.Hour),
		)
		output := captureLogs(t, LogMITMCertInfo)

		if !contains(output, "MITM CA certificate loaded") {
			t.Error("expected 'MITM CA certificate loaded' log line")
		}
		if !contains(output, "EXPIRED") {
			t.Error("expected expiry warning for expired cert")
		}
	})

	t.Run("expiring soon cert", func(t *testing.T) {
		goproxy.GoproxyCa = generateTestCert(t,
			time.Now().Add(-24*time.Hour),
			time.Now().Add(15*24*time.Hour), // 15 days left
		)
		output := captureLogs(t, LogMITMCertInfo)

		if !contains(output, "MITM CA certificate loaded") {
			t.Error("expected 'MITM CA certificate loaded' log line")
		}
		if !contains(output, "expires soon") {
			t.Error("expected 'expires soon' warning for cert expiring in 15 days")
		}
	})

	t.Run("cert with pre-set Leaf", func(t *testing.T) {
		cert := generateTestCert(t,
			time.Now().Add(-24*time.Hour),
			time.Now().Add(365*24*time.Hour),
		)
		// Parse and set Leaf explicitly
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		cert.Leaf = leaf
		goproxy.GoproxyCa = cert

		output := captureLogs(t, LogMITMCertInfo)

		if !contains(output, "MITM CA certificate loaded") {
			t.Error("expected 'MITM CA certificate loaded' log line")
		}
		if !contains(output, "Test CA") {
			t.Error("expected subject to contain 'Test CA'")
		}
	})

	t.Run("empty certificate", func(t *testing.T) {
		goproxy.GoproxyCa = tls.Certificate{}
		output := captureLogs(t, LogMITMCertInfo)

		if output != "" {
			t.Errorf("expected no output for empty certificate, got: %s", output)
		}
	})
}

func TestLoadMITMFromPEM(t *testing.T) {
	// Save and restore the global goproxy CA to avoid test pollution.
	origCa := goproxy.GoproxyCa
	t.Cleanup(func() { goproxy.GoproxyCa = origCa })

	// Write a fresh CA cert+key to temp files.
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	writeTestCAPEM(t, dir, "Custom Test CA", "Custom Test Org")

	t.Run("loads custom cert and replaces embedded default", func(t *testing.T) {
		// Reset to embedded default first.
		goproxy.GoproxyCa = origCa

		if err := loadMITMFromPEM(certPath, keyPath); err != nil {
			t.Fatalf("loadMITMFromPEM() error: %v", err)
		}

		// Parse the loaded certificate.
		if len(goproxy.GoproxyCa.Certificate) == 0 {
			t.Fatal("GoproxyCa has no certificate after loading")
		}
		leaf, err := x509.ParseCertificate(goproxy.GoproxyCa.Certificate[0])
		if err != nil {
			t.Fatalf("parse loaded certificate: %v", err)
		}

		// Verify it's our custom cert, not goproxy's embedded default.
		if leaf.Subject.CommonName != "Custom Test CA" {
			t.Errorf("loaded cert CN = %q, want %q", leaf.Subject.CommonName, "Custom Test CA")
		}
		if leaf.Issuer.Organization[0] != "Custom Test Org" {
			t.Errorf("loaded cert Org = %q, want %q", leaf.Issuer.Organization[0], "Custom Test Org")
		}
		if !leaf.IsCA {
			t.Error("loaded cert is not a CA")
		}

		// Confirm it's different from the embedded goproxy default.
		origLeaf, parseErr := x509.ParseCertificate(origCa.Certificate[0])
		if parseErr != nil {
			t.Fatalf("parse embedded cert: %v", parseErr)
		}
		if leaf.Subject.CommonName == origLeaf.Subject.CommonName {
			t.Error("loaded cert has the same CN as the embedded goproxy default — custom cert not loaded")
		}
	})

	t.Run("error on missing cert file", func(t *testing.T) {
		err := loadMITMFromPEM("/nonexistent/ca.crt", keyPath)
		if err == nil {
			t.Fatal("expected error for missing cert file")
		}
	})

	t.Run("error on missing key file", func(t *testing.T) {
		err := loadMITMFromPEM(certPath, "/nonexistent/ca.key")
		if err == nil {
			t.Fatal("expected error for missing key file")
		}
	})

	t.Run("error on invalid PEM content", func(t *testing.T) {
		badCert := filepath.Join(t.TempDir(), "bad.crt")
		if err := os.WriteFile(badCert, []byte("not-a-cert"), 0o600); err != nil {
			t.Fatal(err)
		}
		err := loadMITMFromPEM(badCert, keyPath)
		if err == nil {
			t.Fatal("expected error for invalid PEM content")
		}
	})
}

func TestLoadTruststoreCerts(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not available")
	}

	dir := t.TempDir()
	_, p12Path := generateTestP12(t, dir, "Test Truststore CA", "Test Org", "testpass")

	t.Run("loads certificates from valid truststore", func(t *testing.T) {
		certs, err := LoadTruststoreCerts(p12Path, "testpass")
		if err != nil {
			t.Fatalf("LoadTruststoreCerts() error = %v", err)
		}
		if len(certs) == 0 {
			t.Fatal("LoadTruststoreCerts() returned no certificates")
		}
		if certs[0].Subject.CommonName != "Test Truststore CA" {
			t.Errorf("cert CN = %q, want %q", certs[0].Subject.CommonName, "Test Truststore CA")
		}
	})

	t.Run("error on wrong password", func(t *testing.T) {
		_, err := LoadTruststoreCerts(p12Path, "wrongpass")
		if err == nil {
			t.Fatal("expected error for wrong password")
		}
	})

	t.Run("error on nonexistent file", func(t *testing.T) {
		_, err := LoadTruststoreCerts("/nonexistent/truststore.p12", "testpass")
		if err == nil {
			t.Fatal("expected error for nonexistent file")
		}
	})

	t.Run("error on invalid data", func(t *testing.T) {
		badPath := filepath.Join(dir, "bad.p12")
		if err := os.WriteFile(badPath, []byte("not-a-p12"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := LoadTruststoreCerts(badPath, "testpass")
		if err == nil {
			t.Fatal("expected error for invalid p12 data")
		}
	})
}

func TestLoadCertPoolWithTruststore(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not available")
	}

	dir := t.TempDir()
	certPath, p12Path := generateTestP12(t, dir, "Pool Test CA", "Test Org", "pooltest")

	t.Run("pool with truststore only", func(t *testing.T) {
		pool := LoadCertPool("", nil, p12Path, "pooltest")
		if pool == nil {
			t.Fatal("LoadCertPool() returned nil")
		}
	})

	t.Run("pool with PEM bundle and truststore", func(t *testing.T) {
		pool := LoadCertPool(certPath, nil, p12Path, "pooltest")
		if pool == nil {
			t.Fatal("LoadCertPool() returned nil")
		}
	})

	t.Run("pool with no extra certs", func(t *testing.T) {
		pool := LoadCertPool("", nil, "", "")
		if pool == nil {
			t.Fatal("LoadCertPool() returned nil")
		}
	})

	t.Run("pool with bad truststore path logs warning", func(t *testing.T) {
		output := captureLogs(t, func() {
			pool := LoadCertPool("", nil, "/nonexistent/truststore.p12", "pass")
			if pool == nil {
				t.Fatal("LoadCertPool() returned nil")
			}
		})
		if !contains(output, "Failed to load truststore") {
			t.Errorf("expected warning about failed truststore load, got: %s", output)
		}
	})
}

func TestLoadCertPoolWithCertPaths(t *testing.T) {
	// Helper: generate a self-signed CA cert PEM and write to file
	writePEMCert := func(t *testing.T, dir, name string) string {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: name},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		path := filepath.Join(dir, name+".crt")
		if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	dir := t.TempDir()
	cert1 := writePEMCert(t, dir, "ca1")
	cert2 := writePEMCert(t, dir, "ca2")

	t.Run("individual cert files appended", func(t *testing.T) {
		pool := LoadCertPool("", []string{cert1, cert2}, "", "")
		if pool == nil {
			t.Fatal("LoadCertPool() returned nil")
		}
	})

	t.Run("combined bundle and cert files", func(t *testing.T) {
		pool := LoadCertPool(cert1, []string{cert2}, "", "")
		if pool == nil {
			t.Fatal("LoadCertPool() returned nil")
		}
	})

	t.Run("unreadable cert path logs warning", func(t *testing.T) {
		output := captureLogs(t, func() {
			pool := LoadCertPool("", []string{"/nonexistent/cert.crt"}, "", "")
			if pool == nil {
				t.Fatal("LoadCertPool() returned nil")
			}
		})
		if !contains(output, "Failed to read CA cert") {
			t.Errorf("expected warning about unreadable cert, got: %s", output)
		}
	})

	t.Run("invalid PEM content logs warning", func(t *testing.T) {
		badPath := filepath.Join(dir, "bad.crt")
		if err := os.WriteFile(badPath, []byte("not-a-pem"), 0o600); err != nil {
			t.Fatal(err)
		}
		output := captureLogs(t, func() {
			pool := LoadCertPool("", []string{badPath}, "", "")
			if pool == nil {
				t.Fatal("LoadCertPool() returned nil")
			}
		})
		if !contains(output, "Failed to parse CA cert") {
			t.Errorf("expected warning about invalid PEM, got: %s", output)
		}
	})
}

func TestSignHostECDSA(t *testing.T) {
	ca := generateTestCert(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	cert, err := SignHost(ca, []string{"example.com", "www.example.com"}, "My Custom Org")
	if err != nil {
		t.Fatalf("SignHost: %v", err)
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	// Verify Organization
	if len(leaf.Subject.Organization) != 1 || leaf.Subject.Organization[0] != "My Custom Org" {
		t.Errorf("Organization = %v, want [My Custom Org]", leaf.Subject.Organization)
	}

	// Verify CommonName
	if leaf.Subject.CommonName != "example.com" {
		t.Errorf("CommonName = %q, want %q", leaf.Subject.CommonName, "example.com")
	}

	// Verify DNSNames
	if !slices.Contains(leaf.DNSNames, "example.com") || !slices.Contains(leaf.DNSNames, "www.example.com") {
		t.Errorf("DNSNames = %v, want [example.com www.example.com]", leaf.DNSNames)
	}

	// Verify key type matches CA (ECDSA)
	if _, ok := cert.PrivateKey.(*ecdsa.PrivateKey); !ok {
		t.Errorf("leaf key type = %T, want *ecdsa.PrivateKey", cert.PrivateKey)
	}

	// Verify signed by CA
	caCert, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Errorf("leaf not signed by CA: %v", err)
	}

	// Verify chain includes CA cert
	if len(cert.Certificate) != 2 {
		t.Errorf("cert chain length = %d, want 2", len(cert.Certificate))
	}
}

func TestSignHostRSA(t *testing.T) {
	// Generate RSA CA
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "RSA CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	ca := tls.Certificate{
		Certificate: [][]byte{caDER},
		PrivateKey:  caKey,
	}

	cert, err := SignHost(ca, []string{"rsa.example.com"}, "RSA Org")
	if err != nil {
		t.Fatalf("SignHost: %v", err)
	}

	if _, ok := cert.PrivateKey.(*rsa.PrivateKey); !ok {
		t.Errorf("leaf key type = %T, want *rsa.PrivateKey", cert.PrivateKey)
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if leaf.Subject.Organization[0] != "RSA Org" {
		t.Errorf("Organization = %v, want [RSA Org]", leaf.Subject.Organization)
	}
}

func TestSignHostIPAddress(t *testing.T) {
	ca := generateTestCert(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	cert, err := SignHost(ca, []string{"10.0.0.1"}, "IP Org")
	if err != nil {
		t.Fatalf("SignHost: %v", err)
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0].String() != "10.0.0.1" {
		t.Errorf("IPAddresses = %v, want [10.0.0.1]", leaf.IPAddresses)
	}
	if len(leaf.DNSNames) != 0 {
		t.Errorf("DNSNames = %v, want empty", leaf.DNSNames)
	}
}

func TestMitmTLSConfigFromCA(t *testing.T) {
	ca := generateTestCert(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	tlsConfigFn := MitmTLSConfigFromCA(&ca, "Test MITM Org")

	// First call — generates cert
	cfg1, err := tlsConfigFn("example.com:443", nil)
	if err != nil {
		t.Fatalf("tlsConfigFn: %v", err)
	}
	if len(cfg1.Certificates) != 1 {
		t.Fatalf("certificates count = %d, want 1", len(cfg1.Certificates))
	}

	leaf, err := x509.ParseCertificate(cfg1.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if leaf.Subject.Organization[0] != "Test MITM Org" {
		t.Errorf("Organization = %v, want [Test MITM Org]", leaf.Subject.Organization)
	}
	if !slices.Contains(leaf.DNSNames, "example.com") {
		t.Errorf("DNSNames = %v, want [example.com]", leaf.DNSNames)
	}

	// Second call — should return cached cert
	cfg2, err := tlsConfigFn("example.com:443", nil)
	if err != nil {
		t.Fatalf("tlsConfigFn (cached): %v", err)
	}
	leaf2, err := x509.ParseCertificate(cfg2.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf2: %v", err)
	}
	if leaf.SerialNumber.Cmp(leaf2.SerialNumber) != 0 {
		t.Error("second call returned different cert, expected cached")
	}

	// Different host — should generate new cert
	cfg3, err := tlsConfigFn("other.com", nil)
	if err != nil {
		t.Fatalf("tlsConfigFn (other host): %v", err)
	}
	leaf3, err := x509.ParseCertificate(cfg3.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf3: %v", err)
	}
	if !slices.Contains(leaf3.DNSNames, "other.com") {
		t.Errorf("DNSNames = %v, want [other.com]", leaf3.DNSNames)
	}
}

func TestGenerateKeyPair(t *testing.T) {
	tests := []struct {
		algo    string
		wantErr bool
	}{
		{"rsa-2048", false},
		{"rsa-4096", false},
		{"ecdsa-p256", false},
		{"ecdsa-p384", false},
		{"ed25519", false},
		{"invalid", true},
	}
	for _, tt := range tests {
		t.Run(tt.algo, func(t *testing.T) {
			key, err := generateKeyPair(tt.algo)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if key == nil {
				t.Fatal("key is nil")
			}
		})
	}
}

func TestRunGencertRootCA(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "root.crt")
	keyPath := filepath.Join(dir, "root.key")

	err := RunGencert([]string{
		"--type", "root",
		"--key-algo", "ecdsa-p256",
		"--cn", "Test Root CA",
		"--org", "Test Org",
		"--country", "CH",
		"--validity", "365",
		"--out-cert", certPath,
		"--out-key", keyPath,
	})
	if err != nil {
		t.Fatalf("RunGencert failed: %v", err)
	}

	// Verify certificate file
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("expected CERTIFICATE PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	if !cert.IsCA {
		t.Error("expected IsCA=true")
	}
	if cert.Subject.CommonName != "Test Root CA" {
		t.Errorf("CN = %q, want %q", cert.Subject.CommonName, "Test Root CA")
	}
	if cert.Subject.Organization[0] != "Test Org" {
		t.Errorf("Org = %q, want %q", cert.Subject.Organization[0], "Test Org")
	}
	if cert.Subject.Country[0] != "CH" {
		t.Errorf("Country = %q, want %q", cert.Subject.Country[0], "CH")
	}
	if cert.Issuer.CommonName != cert.Subject.CommonName {
		t.Errorf("self-signed: issuer CN %q != subject CN %q", cert.Issuer.CommonName, cert.Subject.CommonName)
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("expected KeyUsageCertSign")
	}

	// Verify key file
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		t.Fatal("expected PRIVATE KEY PEM block")
	}
}

func TestRunGencertIntermediateCA(t *testing.T) {
	dir := t.TempDir()

	// Generate root CA first
	rootCertPath := filepath.Join(dir, "root.crt")
	rootKeyPath := filepath.Join(dir, "root.key")
	err := RunGencert([]string{
		"--type", "root",
		"--key-algo", "ecdsa-p256",
		"--cn", "Test Root CA",
		"--org", "Test Org",
		"--out-cert", rootCertPath,
		"--out-key", rootKeyPath,
	})
	if err != nil {
		t.Fatalf("generate root CA: %v", err)
	}

	// Generate intermediate CA
	intCertPath := filepath.Join(dir, "int.crt")
	intKeyPath := filepath.Join(dir, "int.key")
	chainPath := filepath.Join(dir, "chain.crt")
	err = RunGencert([]string{
		"--type", "intermediate",
		"--signing-cert", rootCertPath,
		"--signing-key", rootKeyPath,
		"--key-algo", "ecdsa-p256",
		"--cn", "Test Intermediate CA",
		"--org", "Test Org",
		"--max-path-len", "0",
		"--validity", "180",
		"--out-cert", intCertPath,
		"--out-key", intKeyPath,
		"--out-chain", chainPath,
	})
	if err != nil {
		t.Fatalf("generate intermediate CA: %v", err)
	}

	// Verify intermediate certificate
	intCertPEM, err := os.ReadFile(intCertPath)
	if err != nil {
		t.Fatalf("read intermediate cert: %v", err)
	}
	block, _ := pem.Decode(intCertPEM)
	intCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse intermediate cert: %v", err)
	}

	if !intCert.IsCA {
		t.Error("intermediate: expected IsCA=true")
	}
	if intCert.Subject.CommonName != "Test Intermediate CA" {
		t.Errorf("intermediate CN = %q", intCert.Subject.CommonName)
	}
	if intCert.Issuer.CommonName != "Test Root CA" {
		t.Errorf("intermediate issuer = %q, want %q", intCert.Issuer.CommonName, "Test Root CA")
	}
	if intCert.MaxPathLen != 0 || !intCert.MaxPathLenZero {
		t.Errorf("MaxPathLen = %d, MaxPathLenZero = %v", intCert.MaxPathLen, intCert.MaxPathLenZero)
	}

	// Verify chain file contains both certs
	chainPEM, err := os.ReadFile(chainPath)
	if err != nil {
		t.Fatalf("read chain: %v", err)
	}
	var certCount int
	rest := chainPEM
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type == "CERTIFICATE" {
			certCount++
		}
	}
	if certCount != 2 {
		t.Errorf("chain contains %d certs, want 2", certCount)
	}

	// Verify the chain validates: intermediate signed by root
	rootCertPEM, err := os.ReadFile(rootCertPath)
	if err != nil {
		t.Fatalf("read root cert: %v", err)
	}
	rootBlock, _ := pem.Decode(rootCertPEM)
	rootCert, err := x509.ParseCertificate(rootBlock.Bytes)
	if err != nil {
		t.Fatalf("parse root cert: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(rootCert)
	_, err = intCert.Verify(x509.VerifyOptions{Roots: pool})
	if err != nil {
		t.Errorf("intermediate cert verification failed: %v", err)
	}
}

func TestRunGencertPKCS12Output(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	p12Path := filepath.Join(dir, "ca.p12")

	err := RunGencert([]string{
		"--type", "root",
		"--key-algo", "ecdsa-p256",
		"--cn", "Test P12 CA",
		"--out-cert", certPath,
		"--out-key", keyPath,
		"--out-p12", p12Path,
		"--p12-password", "testpass",
	})
	if err != nil {
		t.Fatalf("RunGencert failed: %v", err)
	}

	// Verify PKCS#12 file is valid by reading it back
	p12Data, err := os.ReadFile(p12Path)
	if err != nil {
		t.Fatalf("read p12: %v", err)
	}
	if len(p12Data) == 0 {
		t.Fatal("p12 file is empty")
	}

	// Decode the PKCS#12 to verify it's valid
	privKey, cert, err := gopkcs12.Decode(p12Data, "testpass")
	if err != nil {
		t.Fatalf("decode p12: %v", err)
	}
	if privKey == nil {
		t.Error("p12: private key is nil")
	}
	if cert == nil {
		t.Fatal("p12: certificate is nil")
	}
	if cert.Subject.CommonName != "Test P12 CA" {
		t.Errorf("p12 cert CN = %q, want %q", cert.Subject.CommonName, "Test P12 CA")
	}
}

func TestRunGencertClientTrustBundle(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "root.crt")
	keyPath := filepath.Join(dir, "root.key")
	clientBundlePath := filepath.Join(dir, "trust.pem")
	clientP12Path := filepath.Join(dir, "truststore.p12")

	err := RunGencert([]string{
		"--type", "root",
		"--key-algo", "ecdsa-p256",
		"--cn", "Test Trust CA",
		"--out-cert", certPath,
		"--out-key", keyPath,
		"--out-client-bundle", clientBundlePath,
		"--out-client-p12", clientP12Path,
		"--client-p12-password", "trustpass",
	})
	if err != nil {
		t.Fatalf("RunGencert failed: %v", err)
	}

	// Verify client PEM bundle
	bundlePEM, err := os.ReadFile(clientBundlePath)
	if err != nil {
		t.Fatalf("read client bundle: %v", err)
	}
	block, _ := pem.Decode(bundlePEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("client bundle: expected CERTIFICATE PEM block")
	}
	bundleCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse bundle cert: %v", err)
	}
	if bundleCert.Subject.CommonName != "Test Trust CA" {
		t.Errorf("client bundle CN = %q, want %q", bundleCert.Subject.CommonName, "Test Trust CA")
	}

	// Verify client PKCS#12 truststore
	tsData, err := os.ReadFile(clientP12Path)
	if err != nil {
		t.Fatalf("read client p12: %v", err)
	}
	if len(tsData) == 0 {
		t.Fatal("client p12 is empty")
	}

	// Decode the truststore to verify it contains the CA cert
	certs, err := gopkcs12.DecodeTrustStore(tsData, "trustpass")
	if err != nil {
		t.Fatalf("decode client truststore: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("truststore has %d certs, want 1", len(certs))
	}
	if certs[0].Subject.CommonName != "Test Trust CA" {
		t.Errorf("truststore cert CN = %q, want %q", certs[0].Subject.CommonName, "Test Trust CA")
	}
}

func TestRunGencertAllKeyAlgorithms(t *testing.T) {
	algos := []string{"rsa-2048", "rsa-4096", "ecdsa-p256", "ecdsa-p384", "ed25519"}
	for _, algo := range algos {
		t.Run(algo, func(t *testing.T) {
			dir := t.TempDir()
			err := RunGencert([]string{
				"--type", "root",
				"--key-algo", algo,
				"--cn", "Test " + algo,
				"--out-cert", filepath.Join(dir, "ca.crt"),
				"--out-key", filepath.Join(dir, "ca.key"),
			})
			if err != nil {
				t.Fatalf("RunGencert with %s failed: %v", algo, err)
			}

			// Verify the cert can be loaded as MITM CA
			certPEM, readErr := os.ReadFile(filepath.Join(dir, "ca.crt"))
			if readErr != nil {
				t.Fatalf("read cert: %v", readErr)
			}
			keyPEM, readErr := os.ReadFile(filepath.Join(dir, "ca.key"))
			if readErr != nil {
				t.Fatalf("read key: %v", readErr)
			}
			tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
			if err != nil {
				t.Fatalf("X509KeyPair failed: %v", err)
			}
			leaf, parseErr := x509.ParseCertificate(tlsCert.Certificate[0])
			if parseErr != nil {
				t.Fatalf("parse cert: %v", parseErr)
			}
			if !leaf.IsCA {
				t.Error("expected IsCA=true")
			}
		})
	}
}

func TestRunGencertValidationErrors(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	tests := []struct {
		name string
		args []string
	}{
		{
			"invalid type",
			[]string{"--type", "invalid", "--out-cert", certPath, "--out-key", keyPath},
		},
		{
			"intermediate missing signing-cert",
			[]string{"--type", "intermediate", "--signing-key", "some.key", "--out-cert", certPath, "--out-key", keyPath},
		},
		{
			"intermediate missing signing-key",
			[]string{"--type", "intermediate", "--signing-cert", "some.crt", "--out-cert", certPath, "--out-key", keyPath},
		},
		{
			"p12 missing password",
			[]string{"--type", "root", "--out-p12", "ca.p12", "--out-cert", certPath, "--out-key", keyPath},
		},
		{
			"invalid key algo",
			[]string{"--type", "root", "--key-algo", "dsa-1024", "--out-cert", certPath, "--out-key", keyPath},
		},
		{
			"empty cn",
			[]string{"--type", "root", "--cn", "", "--out-cert", certPath, "--out-key", keyPath},
		},
		{
			"negative validity",
			[]string{"--type", "root", "--validity", "-1", "--out-cert", certPath, "--out-key", keyPath},
		},
		{
			"zero validity",
			[]string{"--type", "root", "--validity", "0", "--out-cert", certPath, "--out-key", keyPath},
		},
		{
			"invalid max-path-len",
			[]string{"--type", "root", "--max-path-len", "-2", "--out-cert", certPath, "--out-key", keyPath},
		},
		{
			"country code too long",
			[]string{"--type", "root", "--country", "CHE", "--out-cert", certPath, "--out-key", keyPath},
		},
		{
			"country code too short",
			[]string{"--type", "root", "--country", "C", "--out-cert", certPath, "--out-key", keyPath},
		},
		{
			"intermediate signing-cert not found",
			[]string{"--type", "intermediate", "--signing-cert", "/nonexistent/ca.crt", "--signing-key", "/nonexistent/ca.key", "--out-cert", certPath, "--out-key", keyPath},
		},
		{
			"output path conflict cert and key",
			[]string{"--type", "root", "--out-cert", certPath, "--out-key", certPath},
		},
		{
			"output path conflict cert and chain",
			[]string{"--type", "root", "--out-cert", certPath, "--out-key", keyPath, "--out-chain", certPath},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := RunGencert(tt.args); err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestRunGencertHelpReturnsNil(t *testing.T) {
	if err := RunGencert([]string{"--help"}); err != nil {
		t.Errorf("--help should return nil, got %v", err)
	}
}

func TestRunGencertIntermediateClientTrustBundle(t *testing.T) {
	dir := t.TempDir()

	// Generate root
	rootCertPath := filepath.Join(dir, "root.crt")
	rootKeyPath := filepath.Join(dir, "root.key")
	if err := RunGencert([]string{
		"--type", "root", "--key-algo", "ecdsa-p256",
		"--cn", "Root CA", "--out-cert", rootCertPath, "--out-key", rootKeyPath,
	}); err != nil {
		t.Fatalf("generate root: %v", err)
	}

	// Generate intermediate with client trust bundle
	clientBundlePath := filepath.Join(dir, "client-trust.pem")
	clientP12Path := filepath.Join(dir, "client-trust.p12")
	if err := RunGencert([]string{
		"--type", "intermediate",
		"--signing-cert", rootCertPath, "--signing-key", rootKeyPath,
		"--key-algo", "ecdsa-p256", "--cn", "Intermediate CA",
		"--out-cert", filepath.Join(dir, "int.crt"),
		"--out-key", filepath.Join(dir, "int.key"),
		"--out-client-bundle", clientBundlePath,
		"--out-client-p12", clientP12Path,
		"--client-p12-password", "changeit",
	}); err != nil {
		t.Fatalf("generate intermediate: %v", err)
	}

	// Client trust bundle for intermediate should contain the root CA
	bundlePEM, err := os.ReadFile(clientBundlePath)
	if err != nil {
		t.Fatalf("read client bundle: %v", err)
	}
	block, _ := pem.Decode(bundlePEM)
	bundleCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse bundle cert: %v", err)
	}
	if bundleCert.Subject.CommonName != "Root CA" {
		t.Errorf("client bundle should contain root CA, got CN=%q", bundleCert.Subject.CommonName)
	}

	// Client P12 truststore should also contain the root CA
	tsData, err := os.ReadFile(clientP12Path)
	if err != nil {
		t.Fatalf("read client p12: %v", err)
	}
	certs, err := gopkcs12.DecodeTrustStore(tsData, "changeit")
	if err != nil {
		t.Fatalf("decode truststore: %v", err)
	}
	if len(certs) != 1 || certs[0].Subject.CommonName != "Root CA" {
		t.Errorf("truststore should contain root CA, got %v", certs)
	}
}
