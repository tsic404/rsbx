package rpc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testCertificate writes a self-signed certificate and key and returns their
// paths, so the config cases run against real PEM rather than a stub.
func testCertificate(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "rsbx-test"},
		DNSNames:              []string{"rsbx-test"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// A client that verifies the server with no trust anchor is a configuration
// error, not a connect-time certificate failure: it must be refused while the
// transport is built.
func TestClientTLSWithoutCAIsRefused(t *testing.T) {
	config, err := TLSConfig("", "", "", "daemon", false, false)
	if err == nil {
		t.Fatalf("client TLS with no CA produced a config: %+v", config)
	}
	if !strings.Contains(err.Error(), "CA") {
		t.Fatalf("error does not name the missing CA: %v", err)
	}
}

// tls_skip_verify is the explicit local-test escape hatch: no CA is required,
// and the config must actually say verification is off.
func TestClientTLSWithoutCAWithSkipVerifyIsAllowed(t *testing.T) {
	config, err := TLSConfig("", "", "", "daemon", false, true)
	if err != nil {
		t.Fatalf("skip-verify client was refused: %v", err)
	}
	if !config.InsecureSkipVerify {
		t.Fatal("skip-verify client would still verify the server")
	}
	if config.RootCAs != nil {
		t.Fatal("skip-verify client carries a root pool it cannot use")
	}
}

func TestClientTLSWithCAVerifies(t *testing.T) {
	certPath, _ := testCertificate(t)
	config, err := TLSConfig(certPath, "", "", "daemon", false, false)
	if err != nil {
		t.Fatal(err)
	}
	if config.InsecureSkipVerify {
		t.Fatal("client with a CA must verify the server")
	}
	if config.RootCAs == nil || len(config.RootCAs.Subjects()) != 1 {
		t.Fatalf("root pool does not carry the configured CA: %+v", config.RootCAs)
	}
}

func TestClientTLSRejectsSkipVerifyTogetherWithCA(t *testing.T) {
	certPath, _ := testCertificate(t)
	if _, err := TLSConfig(certPath, "", "", "daemon", false, true); err == nil {
		t.Fatal("skip-verify with a CA was accepted: the two settings contradict each other")
	}
}

func TestServerTLSRequiresClientCA(t *testing.T) {
	if _, err := TLSConfig("", "", "", "", true, false); err == nil || !strings.Contains(err.Error(), "client CA") {
		t.Fatalf("server TLS without a client CA was accepted: %v", err)
	}
}

func TestServerTLSRequiresMutualVerification(t *testing.T) {
	certPath, keyPath := testCertificate(t)
	config, err := TLSConfig(certPath, certPath, keyPath, "", true, false)
	if err != nil {
		t.Fatal(err)
	}
	if config.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("server does not require a client certificate: %v", config.ClientAuth)
	}
	if config.ClientCAs == nil || len(config.ClientCAs.Subjects()) != 1 {
		t.Fatal("server client pool does not carry the configured CA")
	}
}

func TestTLSCertificateAndKeyMustTravelTogether(t *testing.T) {
	certPath, _ := testCertificate(t)
	if _, err := TLSConfig(certPath, certPath, "", "daemon", false, false); err == nil {
		t.Fatal("certificate without a key was accepted")
	}
}

func TestTLSRejectsCAFileWithoutCertificates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(path, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := TLSConfig(path, "", "", "daemon", false, false); err == nil {
		t.Fatal("a CA file without certificates was accepted")
	}
}

func TestTLSReportsUnreadableCA(t *testing.T) {
	if _, err := TLSConfig(filepath.Join(t.TempDir(), "missing.pem"), "", "", "daemon", false, false); err == nil {
		t.Fatal("a missing CA file was accepted")
	}
}
