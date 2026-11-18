package rpc

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

func TLSConfig(caPath, certPath, keyPath, serverName string, server bool, skipVerify bool) (*tls.Config, error) {
	if (certPath == "") != (keyPath == "") || !server && skipVerify && caPath != "" {
		return nil, fmt.Errorf("TLS requires CA, certificate and private key")
	}
	// A client that verifies the server needs a trust anchor. An empty pool
	// would let the config construct and then fail every handshake with an
	// x509 error at connect time, which reads as a network fault rather than
	// the configuration mistake it is.
	if !server && !skipVerify && caPath == "" {
		return nil, fmt.Errorf("client TLS requires a CA file to verify the server: set tls_ca, " +
			"or tls_skip_verify for a local test")
	}
	roots := x509.NewCertPool()
	if caPath != "" {
		data, err := os.ReadFile(caPath)
		if err != nil {
			return nil, err
		}
		if !roots.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("CA file contains no certificates")
		}
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: serverName, InsecureSkipVerify: skipVerify}
	if certPath != "" {
		certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, err
		}
		config.Certificates = []tls.Certificate{certificate}
	}
	if server {
		if caPath == "" {
			return nil, fmt.Errorf("server TLS requires client CA")
		}
		config.ClientCAs = roots
		config.ClientAuth = tls.RequireAndVerifyClientCert
	} else {
		if !skipVerify {
			config.RootCAs = roots
		}
	}
	return config, nil
}
