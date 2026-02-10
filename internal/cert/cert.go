// Package cert provides MITM certificate loading, signing, TLS pool building,
// and outbound TLS configuration for the proxy.
package cert

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/elazarl/goproxy"
	gopkcs12 "software.sslmate.com/src/go-pkcs12"

	"go-egress-proxy/internal/config"
)

// LoadMITMCertificate loads the MITM CA certificate and key into goproxy.
// It supports either PEM cert+key files or a PKCS#12 (.p12) keystore.
func LoadMITMCertificate(cfg config.Config) error {
	if cfg.Proxy.MitmKeystorePath != "" {
		return loadMITMFromKeystore(cfg.Proxy.MitmKeystorePath, cfg.Proxy.MitmKeystorePassword)
	}
	return loadMITMFromPEM(cfg.Proxy.MitmCertPath, cfg.Proxy.MitmKeyPath)
}

func loadMITMFromPEM(certPath, keyPath string) error {
	caCert, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("read certificate: %w", err)
	}
	caKey, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read key: %w", err)
	}

	goproxy.GoproxyCa, err = tls.X509KeyPair(caCert, caKey)
	if err != nil {
		return fmt.Errorf("parse keypair: %w", err)
	}

	return validateMITMCA()
}

func loadMITMFromKeystore(keystorePath, password string) error {
	data, err := os.ReadFile(keystorePath)
	if err != nil {
		return fmt.Errorf("read keystore: %w", err)
	}

	privateKey, cert, err := gopkcs12.Decode(data, password)
	if err != nil {
		return fmt.Errorf("decode keystore: %w", err)
	}

	goproxy.GoproxyCa = tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  privateKey,
		Leaf:        cert,
	}

	return validateMITMCA()
}

// validateMITMCA checks that the loaded MITM certificate is actually a CA certificate.
// A non-CA certificate would silently produce per-domain certs that clients reject.
func validateMITMCA() error {
	leaf := goproxy.GoproxyCa.Leaf
	if leaf == nil {
		var err error
		leaf, err = x509.ParseCertificate(goproxy.GoproxyCa.Certificate[0])
		if err != nil {
			return fmt.Errorf("parse MITM certificate for validation: %w", err)
		}
	}
	if !leaf.IsCA {
		return errors.New("MITM certificate is not a CA certificate (BasicConstraints CA:TRUE is required); " +
			"per-domain certificates signed by a non-CA will be rejected by clients")
	}
	return nil
}

// LogMITMCertInfo parses the loaded MITM CA certificate and logs its details.
func LogMITMCertInfo() {
	if len(goproxy.GoproxyCa.Certificate) == 0 {
		return
	}

	leaf := goproxy.GoproxyCa.Leaf
	if leaf == nil {
		var err error
		leaf, err = x509.ParseCertificate(goproxy.GoproxyCa.Certificate[0])
		if err != nil {
			slog.Warn("Failed to parse MITM CA certificate for logging", "err", err)
			return
		}
	}

	slog.Info("MITM CA certificate loaded",
		"subject", leaf.Subject.String(),
		"issuer", leaf.Issuer.String(),
		"serial", leaf.SerialNumber.String(),
		"not_before", leaf.NotBefore.Format(time.RFC3339),
		"not_after", leaf.NotAfter.Format(time.RFC3339),
		"is_ca", leaf.IsCA)

	if time.Now().After(leaf.NotAfter) {
		slog.Warn("MITM CA certificate has EXPIRED", "expired_at", leaf.NotAfter.Format(time.RFC3339))
	} else if time.Until(leaf.NotAfter) < 30*24*time.Hour {
		slog.Warn("MITM CA certificate expires soon", "expires_in_days", int(time.Until(leaf.NotAfter).Hours()/24))
	}
}

// SignHost generates a leaf TLS certificate for the given hosts, signed by the CA,
// using the specified Organization. The key type matches the CA key (RSA, ECDSA, or Ed25519).
func SignHost(ca tls.Certificate, hosts []string, org string) (*tls.Certificate, error) {
	// Parse the CA certificate
	caCert, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}

	// Generate serial number
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	// Build leaf certificate template
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{org},
			CommonName:   hosts[0],
		},
		NotBefore:             time.Now().Add(-24 * 30 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}

	// Generate key matching the CA key type
	var privKey any
	switch ca.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		privKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case ed25519.PrivateKey:
		_, privKey, err = ed25519.GenerateKey(rand.Reader)
	default: // RSA or unknown → RSA 2048
		privKey, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	// Extract public key
	var pubKey any
	switch k := privKey.(type) {
	case *ecdsa.PrivateKey:
		pubKey = &k.PublicKey
	case ed25519.PrivateKey:
		pubKey = k.Public()
	case *rsa.PrivateKey:
		pubKey = &k.PublicKey
	}

	// Sign the leaf certificate with the CA
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, pubKey, ca.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("sign certificate: %w", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDER, ca.Certificate[0]},
		PrivateKey:  privKey,
	}, nil
}

// MitmTLSConfigFromCA returns a TLS config callback that generates leaf certificates
// with the specified Organization, using the given CA. A sync.Map cache avoids
// regenerating certificates for the same host.
func MitmTLSConfigFromCA(ca *tls.Certificate, org string) func(host string, ctx *goproxy.ProxyCtx) (*tls.Config, error) {
	certCache := &sync.Map{}
	return func(host string, _ *goproxy.ProxyCtx) (*tls.Config, error) {
		// Strip port if present
		hostname, _, err := net.SplitHostPort(host)
		if err != nil {
			hostname = host
		}

		if cached, ok := certCache.Load(hostname); ok {
			cert := cached.(*tls.Certificate) //nolint:errcheck // stored type is always *tls.Certificate
			return &tls.Config{
				Certificates: []tls.Certificate{*cert},
				MinVersion:   tls.VersionTLS12,
			}, nil
		}

		cert, err := SignHost(*ca, []string{hostname}, org)
		if err != nil {
			return nil, err
		}

		certCache.Store(hostname, cert)
		return &tls.Config{
			Certificates: []tls.Certificate{*cert},
			MinVersion:   tls.VersionTLS12,
		}, nil
	}
}

// LoadCertPool loads the system CA pool, optionally appends a PEM CA bundle, individual CA cert
// files, and/or certificates from a PKCS#12 truststore. All sources are additive.
func LoadCertPool(caBundle string, certPaths []string, truststorePath, truststorePassword string) *x509.CertPool {
	pool, err := x509.SystemCertPool()
	if err != nil {
		slog.Warn("Failed to load system cert pool, using empty pool", "err", err)
		pool = x509.NewCertPool()
	}
	if caBundle != "" {
		ca, readErr := os.ReadFile(caBundle)
		if readErr != nil {
			slog.Warn("Failed to read CA bundle", "path", caBundle, "err", readErr)
		} else if !pool.AppendCertsFromPEM(ca) {
			slog.Warn("Failed to parse CA bundle", "path", caBundle)
		}
	}
	for _, p := range certPaths {
		if strings.TrimSpace(p) == "" {
			continue
		}
		ca, readErr := os.ReadFile(p)
		if readErr != nil {
			slog.Warn("Failed to read CA cert", "path", p, "err", readErr)
			continue
		}
		if !pool.AppendCertsFromPEM(ca) {
			slog.Warn("Failed to parse CA cert", "path", p)
		}
	}
	if truststorePath != "" {
		certs, tsErr := LoadTruststoreCerts(truststorePath, truststorePassword)
		if tsErr != nil {
			slog.Warn("Failed to load truststore", "path", truststorePath, "err", tsErr)
		} else {
			for _, cert := range certs {
				pool.AddCert(cert)
			}
			slog.Info("Loaded truststore certificates", "path", truststorePath, "count", len(certs))
		}
	}
	return pool
}

// BuildOutboundTLSConfig builds a tls.Config for outbound connections from the given proxy config.
func BuildOutboundTLSConfig(cfg config.Config) *tls.Config {
	tlsCfg := &tls.Config{
		RootCAs:    LoadCertPool(cfg.Proxy.OutgoingCABundle, cfg.Proxy.OutgoingCA, cfg.Proxy.OutgoingTruststorePath, cfg.Proxy.OutgoingTruststorePassword),
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
	}
	if cfg.Proxy.InsecureSkipVerify {
		slog.Warn("Global insecure_skip_verify is ENABLED — upstream TLS certificate verification is disabled")
		tlsCfg.InsecureSkipVerify = true //nolint:gosec // intentional: user-configured global insecure for dev/test
	}
	return tlsCfg
}

// LoadTruststoreCerts extracts CA certificates from a PKCS#12 (.p12) truststore.
func LoadTruststoreCerts(path, password string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read truststore: %w", err)
	}

	// Try truststore format first (cert-only bags), then fall back to keystore
	// format (cert+key bags) since users may provide either type.
	certs, err := gopkcs12.DecodeTrustStore(data, password)
	if err != nil {
		// Fall back to keystore format: extract the leaf cert
		_, cert, decodeErr := gopkcs12.Decode(data, password)
		if decodeErr != nil {
			return nil, fmt.Errorf("decode truststore: %w", err)
		}
		certs = []*x509.Certificate{cert}
	}

	if len(certs) == 0 {
		return nil, errors.New("truststore contains no certificates")
	}
	return certs, nil
}
