package cert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"strings"
	"time"

	gopkcs12 "software.sslmate.com/src/go-pkcs12"
)

// RunGencert generates a root or intermediate CA certificate with optional client trust bundles.
func RunGencert(args []string) error {
	fs := flag.NewFlagSet("gencert", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: %s gencert [flags]

Generate root or intermediate CA certificates for MITM proxy operation.

Examples:
  # Generate a root CA
  %[1]s gencert --type root --cn "My Root CA" --org "ACME Corp"

  # Generate an intermediate CA signed by the root
  %[1]s gencert --type intermediate \
    --signing-cert root-ca.crt --signing-key root-ca.key \
    --cn "My MITM CA" --org "ACME Corp" --max-path-len 0 \
    --out-cert mitm-ca.crt --out-key mitm-ca.key --out-chain mitm-chain.crt

  # Generate root CA with client trust bundles for Java
  %[1]s gencert --type root --cn "My Root CA" \
    --out-client-bundle trust.pem \
    --out-client-p12 truststore.p12 --client-p12-password changeit

Flags:
`, os.Args[0])
		fs.PrintDefaults()
	}

	certType := fs.String("type", "root", "certificate type: root or intermediate")
	keyAlgo := fs.String("key-algo", "ecdsa-p256", "key algorithm: rsa-2048, rsa-4096, ecdsa-p256, ecdsa-p384, ed25519")
	cn := fs.String("cn", "MITM Proxy CA", "CommonName for the certificate subject")
	org := fs.String("org", "MITM Proxy", "Organization for the certificate subject")
	country := fs.String("country", "", "Country code (e.g. CH)")
	validity := fs.Int("validity", 3650, "certificate validity in days")
	maxPathLen := fs.Int("max-path-len", -1, "BasicConstraints MaxPathLen (-1=unlimited, 0=leaf-signing only)")
	signingCert := fs.String("signing-cert", "", "parent CA certificate path (required for intermediate)")
	signingKey := fs.String("signing-key", "", "parent CA private key path (required for intermediate)")

	outCert := fs.String("out-cert", "ca.crt", "output certificate path (PEM)")
	outKey := fs.String("out-key", "ca.key", "output private key path (PEM)")
	outChain := fs.String("out-chain", "", "output full chain (cert + signing CA chain, PEM)")
	outP12 := fs.String("out-p12", "", "output PKCS#12 keystore with cert+key (for mitm_keystore_path)")
	p12Password := fs.String("p12-password", "", "password for --out-p12 keystore")

	outClientBundle := fs.String("out-client-bundle", "", "output client trust bundle (PEM, root CA for client distribution)")
	outClientP12 := fs.String("out-client-p12", "", "output client PKCS#12 truststore (for Java -Djavax.net.ssl.trustStore)")
	clientP12Password := fs.String("client-p12-password", "changeit", "password for --out-client-p12 truststore")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil // usage already printed by FlagSet
		}
		return err
	}

	// Validate flags
	var validationErrors []string

	switch *certType {
	case "root", "intermediate":
	default:
		validationErrors = append(validationErrors, fmt.Sprintf("--type must be 'root' or 'intermediate', got %q", *certType))
	}

	switch *keyAlgo {
	case "rsa-2048", "rsa-4096", "ecdsa-p256", "ecdsa-p384", "ed25519":
	default:
		validationErrors = append(validationErrors, fmt.Sprintf("--key-algo must be one of rsa-2048, rsa-4096, ecdsa-p256, ecdsa-p384, ed25519; got %q", *keyAlgo))
	}

	if *cn == "" {
		validationErrors = append(validationErrors, "--cn must not be empty")
	}
	if *validity <= 0 {
		validationErrors = append(validationErrors, fmt.Sprintf("--validity must be a positive number of days, got %d", *validity))
	}
	if *maxPathLen < -1 {
		validationErrors = append(validationErrors, fmt.Sprintf("--max-path-len must be -1 (unlimited) or >= 0, got %d", *maxPathLen))
	}
	if *country != "" && len(*country) != 2 {
		validationErrors = append(validationErrors, fmt.Sprintf("--country must be a 2-letter ISO 3166-1 code, got %q", *country))
	}

	if *certType == "intermediate" {
		if *signingCert == "" || *signingKey == "" {
			validationErrors = append(validationErrors, "--signing-cert and --signing-key are required for intermediate CA")
		} else {
			if _, err := os.Stat(*signingCert); err != nil {
				validationErrors = append(validationErrors, fmt.Sprintf("--signing-cert file not accessible: %v", err))
			}
			if _, err := os.Stat(*signingKey); err != nil {
				validationErrors = append(validationErrors, fmt.Sprintf("--signing-key file not accessible: %v", err))
			}
		}
	}

	if *outP12 != "" && *p12Password == "" {
		validationErrors = append(validationErrors, "--p12-password is required when using --out-p12")
	}
	if *outClientP12 != "" && *clientP12Password == "" {
		validationErrors = append(validationErrors, "--client-p12-password is required when using --out-client-p12")
	}

	// Check for output path conflicts
	outputs := map[string]string{
		*outCert: "--out-cert",
	}
	outputConflict := func(path, flagName string) {
		if path == "" {
			return
		}
		if existing, ok := outputs[path]; ok {
			validationErrors = append(validationErrors, fmt.Sprintf("%s and %s must not share the same path %q", existing, flagName, path))
		} else {
			outputs[path] = flagName
		}
	}
	outputConflict(*outKey, "--out-key")
	outputConflict(*outChain, "--out-chain")
	outputConflict(*outP12, "--out-p12")
	outputConflict(*outClientBundle, "--out-client-bundle")
	outputConflict(*outClientP12, "--out-client-p12")

	if len(validationErrors) > 0 {
		return fmt.Errorf("invalid flags:\n  - %s", strings.Join(validationErrors, "\n  - "))
	}

	// Generate key pair
	privKey, err := generateKeyPair(*keyAlgo)
	if err != nil {
		return fmt.Errorf("generate key pair: %w", err)
	}

	// Generate random serial number
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generate serial: %w", err)
	}

	// Build CA certificate template
	subject := pkix.Name{
		CommonName:   *cn,
		Organization: []string{*org},
	}
	if *country != "" {
		subject.Country = []string{*country}
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(*validity) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	if *maxPathLen >= 0 {
		tmpl.MaxPathLen = *maxPathLen
		tmpl.MaxPathLenZero = *maxPathLen == 0
	}

	// Determine signer: self-signed for root, parent CA for intermediate
	var (
		signerKey      crypto.PrivateKey
		parentCert     *x509.Certificate
		parentCertsPEM []byte // raw PEM of signing cert file (may contain chain)
	)

	signer, ok := privKey.(crypto.Signer)
	if !ok {
		return errors.New("generated key does not implement crypto.Signer")
	}
	pub := signer.Public()

	if *certType == "root" {
		signerKey = privKey
		parentCert = tmpl // self-signed: template is both subject and issuer
	} else {
		parentCertPEM, readErr := os.ReadFile(*signingCert)
		if readErr != nil {
			return fmt.Errorf("read signing certificate: %w", readErr)
		}
		parentKeyPEM, readErr := os.ReadFile(*signingKey)
		if readErr != nil {
			return fmt.Errorf("read signing key: %w", readErr)
		}

		tlsCert, parseErr := tls.X509KeyPair(parentCertPEM, parentKeyPEM)
		if parseErr != nil {
			return fmt.Errorf("parse signing CA key pair: %w", parseErr)
		}

		parentCert, parseErr = x509.ParseCertificate(tlsCert.Certificate[0])
		if parseErr != nil {
			return fmt.Errorf("parse signing certificate: %w", parseErr)
		}
		if !parentCert.IsCA {
			return errors.New("signing certificate is not a CA certificate (BasicConstraints CA:TRUE required)")
		}

		signerKey = tlsCert.PrivateKey
		parentCertsPEM = parentCertPEM
	}

	// Create the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, pub, signerKey)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("parse generated certificate: %w", err)
	}

	// Marshal private key to PKCS#8
	keyDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}

	// Write certificate PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(*outCert, certPEM, 0644); err != nil { //nolint:gosec // certificate is public
		return fmt.Errorf("write certificate: %w", err)
	}

	// Write private key PEM (restrictive permissions)
	keyPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(*outKey, keyPEMBytes, 0600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}

	slog.Info("Generated CA certificate",
		"type", *certType,
		"cn", cert.Subject.CommonName,
		"serial", hex.EncodeToString(cert.SerialNumber.Bytes()),
		"not_before", cert.NotBefore.Format(time.RFC3339),
		"not_after", cert.NotAfter.Format(time.RFC3339),
		"key_algo", *keyAlgo,
		"is_ca", cert.IsCA,
		"cert_file", *outCert,
		"key_file", *outKey,
	)

	// Write certificate chain (intermediate cert + parent chain)
	if *outChain != "" {
		var chainData []byte
		chainData = append(chainData, certPEM...)
		if parentCertsPEM != nil {
			chainData = append(chainData, parentCertsPEM...)
		}
		if err := os.WriteFile(*outChain, chainData, 0644); err != nil { //nolint:gosec // chain is public
			return fmt.Errorf("write chain: %w", err)
		}
		slog.Info("Wrote certificate chain", "path", *outChain)
	}

	// Write PKCS#12 keystore (cert + key, optionally including parent chain)
	if *outP12 != "" {
		var caCerts []*x509.Certificate
		if *certType == "intermediate" {
			caCerts = append(caCerts, parentCert)
		}
		p12Data, p12Err := gopkcs12.Modern.Encode(privKey, cert, caCerts, *p12Password)
		if p12Err != nil {
			return fmt.Errorf("encode PKCS#12 keystore: %w", p12Err)
		}
		if err := os.WriteFile(*outP12, p12Data, 0600); err != nil {
			return fmt.Errorf("write PKCS#12 keystore: %w", err)
		}
		slog.Info("Wrote PKCS#12 keystore", "path", *outP12)
	}

	// Determine trust anchor for client bundles:
	// - Root CA: the generated cert itself
	// - Intermediate CA: the parent (signing) cert chain
	var trustAnchorCerts []*x509.Certificate
	var trustAnchorPEM []byte
	if *certType == "root" {
		trustAnchorCerts = []*x509.Certificate{cert}
		trustAnchorPEM = certPEM
	} else {
		trustAnchorCerts = []*x509.Certificate{parentCert}
		trustAnchorPEM = parentCertsPEM
	}

	// Write client trust bundle (PEM)
	if *outClientBundle != "" {
		if err := os.WriteFile(*outClientBundle, trustAnchorPEM, 0644); err != nil { //nolint:gosec // trust bundle is public
			return fmt.Errorf("write client trust bundle: %w", err)
		}
		slog.Info("Wrote client trust bundle (PEM)", "path", *outClientBundle)
	}

	// Write client PKCS#12 truststore (for Java keystore import)
	if *outClientP12 != "" {
		tsData, tsErr := gopkcs12.Modern.EncodeTrustStore(trustAnchorCerts, *clientP12Password)
		if tsErr != nil {
			return fmt.Errorf("encode client PKCS#12 truststore: %w", tsErr)
		}
		if err := os.WriteFile(*outClientP12, tsData, 0644); err != nil { //nolint:gosec // truststore is public (no private keys)
			return fmt.Errorf("write client PKCS#12 truststore: %w", err)
		}
		slog.Info("Wrote client PKCS#12 truststore", "path", *outClientP12,
			"usage_direct", fmt.Sprintf("-Djavax.net.ssl.trustStore=%s -Djavax.net.ssl.trustStoreType=PKCS12 -Djavax.net.ssl.trustStorePassword=%s", *outClientP12, *clientP12Password),
			"usage_import", fmt.Sprintf("keytool -importkeystore -srckeystore %s -srcstoretype PKCS12 -srcstorepass %s -destkeystore truststore.jks -deststorepass changeit", *outClientP12, *clientP12Password),
		)
	}

	return nil
}

// generateKeyPair creates a new private key using the specified algorithm.
// Supported algorithms: rsa-2048, rsa-4096, ecdsa-p256, ecdsa-p384, ed25519.
func generateKeyPair(algo string) (crypto.PrivateKey, error) {
	switch algo {
	case "rsa-2048":
		return rsa.GenerateKey(rand.Reader, 2048)
	case "rsa-4096":
		return rsa.GenerateKey(rand.Reader, 4096)
	case "ecdsa-p256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ecdsa-p384":
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "ed25519":
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	default:
		return nil, fmt.Errorf("unsupported key algorithm %q (use rsa-2048, rsa-4096, ecdsa-p256, ecdsa-p384, or ed25519)", algo)
	}
}
