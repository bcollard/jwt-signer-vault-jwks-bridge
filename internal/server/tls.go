package server

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// TLSConfig builds the private listener TLS configuration. The server
// certificate is reloaded from disk when the files change, so a rotated
// Kubernetes Secret is picked up without a restart. When clientCAFile is set,
// client certificates are verified against it if presented.
func TLSConfig(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	if certFile == "" || keyFile == "" {
		return nil, errors.New("the private listener needs a TLS certificate and key")
	}
	rl := &certReloader{certFile: certFile, keyFile: keyFile}
	if err := rl.load(); err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: rl.get,
	}
	if clientCAFile != "" {
		pem, err := os.ReadFile(clientCAFile)
		if err != nil {
			return nil, fmt.Errorf("read client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificate found in %s", clientCAFile)
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.VerifyClientCertIfGiven
	}
	return cfg, nil
}

type certReloader struct {
	certFile, keyFile string

	mu      sync.Mutex
	cert    *tls.Certificate
	modTime time.Time
	checked time.Time
}

func (c *certReloader) load() error {
	st, err := os.Stat(c.certFile)
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
	if err != nil {
		return fmt.Errorf("load TLS key pair: %w", err)
	}
	c.cert, c.modTime = &cert, st.ModTime()
	return nil
}

func (c *certReloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.checked) > 10*time.Second {
		c.checked = time.Now()
		if st, err := os.Stat(c.certFile); err == nil && !st.ModTime().Equal(c.modTime) {
			// Keep serving the previous certificate if the new pair is incomplete.
			_ = c.load()
		}
	}
	return c.cert, nil
}
