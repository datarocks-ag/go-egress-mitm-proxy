// Package cert provides MITM certificate loading, signing, TLS pool building,
// and outbound TLS configuration for the proxy.
package cert

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
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

	ca, err := tls.X509KeyPair(caCert, caKey)
	if err != nil {
		return fmt.Errorf("parse keypair: %w", err)
	}
	if err := validateCA(ca); err != nil {
		return err
	}

	// Assigned only after validation. Writing the global first meant a parse
	// failure replaced the loaded CA with a zero tls.Certificate, and a
	// validation failure left an unusable one installed -- a failed load
	// destroying working state.
	goproxy.GoproxyCa = ca
	return nil
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

	ca := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  privateKey,
		Leaf:        cert,
	}
	if err := validateCA(ca); err != nil {
		return err
	}

	// Assigned only after validation; see loadMITMFromPEM.
	goproxy.GoproxyCa = ca
	return nil
}

// validateCA reports whether ca is usable for signing MITM leaf certificates.
//
// It takes the candidate rather than reading the global so a caller can check
// before installing it. The CA check matters because a non-CA certificate loads
// and signs perfectly well; the leaves it produces are simply rejected by every
// client.
func validateCA(ca tls.Certificate) error {
	if len(ca.Certificate) == 0 {
		return errors.New("MITM certificate contains no certificates")
	}
	leaf := ca.Leaf
	if leaf == nil {
		var err error
		leaf, err = x509.ParseCertificate(ca.Certificate[0])
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

	// Attach the full CA chain, not just ca.Certificate[0]. With a
	// root -> int1 -> int2 hierarchy, gencert --out-chain emits three certs;
	// presenting only leaf + int2 leaves a root-only client unable to build a
	// path, and every handshake fails with "unknown authority".
	chain := make([][]byte, 0, 1+len(ca.Certificate))
	chain = append(chain, certDER)
	chain = append(chain, ca.Certificate...)

	return &tls.Certificate{
		Certificate: chain,
		PrivateKey:  privKey,
	}, nil
}

// MitmTLSConfigFromCA returns a TLS config callback that generates leaf
// certificates with the specified Organization, using the given CA.
//
// store bounds and expires the cache; pass the same store used for
// proxy.CertStore so both signing paths share one caching policy instead of the
// policy depending on whether mitm_org happens to be set.
//
// A nil store falls back to a package-level shared default rather than a fresh
// one. Minting a new cache per call would quietly reintroduce exactly the
// divergence this parameter exists to remove -- two signing paths with separate
// caches -- and would do it invisibly.
func MitmTLSConfigFromCA(ca *tls.Certificate, org string, store *CertStore) func(host string, ctx *goproxy.ProxyCtx) (*tls.Config, error) {
	if store == nil {
		store = sharedDefaultStore()
	}

	// Qualify cache keys with the signing CA and Organization, computed once.
	//
	// A leaf is only interchangeable with another leaf for the same hostname if
	// it was signed by the same CA with the same subject. Keying on hostname
	// alone meant two callers with different CAs shared entries: the second
	// received the first's certificate, wrong issuer and wrong Organization.
	// Latent in production, which has one CA and one call site, but the store is
	// process-wide and nothing prevents a second caller.
	keyPrefix := caCacheKeyPrefix(ca, org)

	return func(host string, _ *goproxy.ProxyCtx) (*tls.Config, error) {
		// Strip port if present
		hostname, _, err := net.SplitHostPort(host)
		if err != nil {
			hostname = host
		}

		cert, err := store.Fetch(keyPrefix+"\x00"+hostname, func() (*tls.Certificate, error) {
			return SignHost(*ca, []string{hostname}, org)
		})
		if err != nil {
			return nil, err
		}

		return &tls.Config{
			Certificates: []tls.Certificate{*cert},
			MinVersion:   tls.VersionTLS12,
		}, nil
	}
}

// caCacheKeyPrefix identifies the signing identity a cached leaf belongs to.
func caCacheKeyPrefix(ca *tls.Certificate, org string) string {
	h := sha256.New()
	for _, der := range ca.Certificate {
		h.Write(der)
		h.Write([]byte{0}) // separator: without it, adjacent DERs and the org concatenate ambiguously
	}
	h.Write([]byte(org))
	return hex.EncodeToString(h.Sum(nil))
}

var (
	defaultStoreOnce sync.Once
	defaultStore     *CertStore
)

// sharedDefaultStore returns the process-wide fallback certificate cache, so
// every caller that does not supply one still converges on a single cache.
func sharedDefaultStore() *CertStore {
	defaultStoreOnce.Do(func() {
		defaultStore = NewCertStore(DefaultCertCacheSize, DefaultCertTTL)
	})
	return defaultStore
}

// LoadCertPool loads the system CA pool, optionally appending a PEM CA bundle,
// individual CA cert files, and/or certificates from a PKCS#12 truststore. All
// sources are additive.
//
// A configured CA source that cannot be loaded is an error, not a warning. It
// previously warned and continued, so a typo'd path or an undecodable truststore
// produced a silently degraded pool: upstream verification then failed for every
// request, which is fail-closed and therefore safe, but the operator saw a WARN
// next to "Configuration reloaded successfully" and an incremented success
// counter. Failing loudly is what makes that diagnosable.
//
// A missing *system* pool is still only a warning: it is not something the
// operator configured, and the explicit sources may well be sufficient.
func LoadCertPool(caBundle string, certPaths []string, truststorePath, truststorePassword string) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		slog.Warn("Failed to load system cert pool, using empty pool", "err", err)
		pool = x509.NewCertPool()
	}
	if caBundle != "" {
		ca, readErr := os.ReadFile(caBundle)
		if readErr != nil {
			return nil, fmt.Errorf("read CA bundle %q: %w", caBundle, readErr)
		}
		if !pool.AppendCertsFromPEM(ca) {
			return nil, fmt.Errorf("CA bundle %q contains no usable PEM certificates", caBundle)
		}
	}
	for _, p := range certPaths {
		if strings.TrimSpace(p) == "" {
			continue
		}
		ca, readErr := os.ReadFile(p)
		if readErr != nil {
			return nil, fmt.Errorf("read CA cert %q: %w", p, readErr)
		}
		if !pool.AppendCertsFromPEM(ca) {
			return nil, fmt.Errorf("CA cert %q contains no usable PEM certificates", p)
		}
	}
	if truststorePath != "" {
		certs, tsErr := LoadTruststoreCerts(truststorePath, truststorePassword)
		if tsErr != nil {
			return nil, fmt.Errorf("load truststore %q: %w", truststorePath, tsErr)
		}
		for _, cert := range certs {
			pool.AddCert(cert)
		}
		slog.Info("Loaded truststore certificates", "path", truststorePath, "count", len(certs))
	}
	return pool, nil
}

// BuildOutboundTLSConfig builds a tls.Config for outbound connections from the
// given proxy config. It fails when a configured CA source cannot be loaded, so
// startup aborts and a reload keeps the previous config instead of installing a
// degraded pool.
func BuildOutboundTLSConfig(cfg config.Config) (*tls.Config, error) {
	pool, err := LoadCertPool(cfg.Proxy.OutgoingCABundle, cfg.Proxy.OutgoingCA, cfg.Proxy.OutgoingTruststorePath, cfg.Proxy.OutgoingTruststorePassword)
	if err != nil {
		return nil, err
	}

	tlsCfg := &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
	}
	if cfg.Proxy.InsecureSkipVerify {
		slog.Warn("Global insecure_skip_verify is ENABLED — upstream TLS certificate verification is disabled")
		tlsCfg.InsecureSkipVerify = true //nolint:gosec // intentional: user-configured global insecure for dev/test
	}
	return tlsCfg, nil
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
