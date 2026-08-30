package satls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"
)

func ensureSelfSignedCertificate(domain, certPath, keyPath, label string) error {
	if certPath == "" || keyPath == "" {
		return fmt.Errorf("satls: missing %s certificate path", label)
	}
	if fileExists(certPath) && fileExists(keyPath) {
		return nil
	}
	if domain == "" {
		return fmt.Errorf("satls: missing %s certificate server name", label)
	}
	if err := generateSelfSigned(domain, certPath, keyPath); err != nil {
		return fmt.Errorf("satls: generate %s self-signed certificate: %w", label, err)
	}
	return nil
}

func generateSelfSigned(domain, certPath, keyPath string) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		Version:      3,
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			CommonName: domain,
		},
		DNSNames:              []string{domain},
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(5, 0, 0),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return err
	}
	certFile, err := os.OpenFile(certPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer certFile.Close()
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return err
	}
	keyFile, err := os.OpenFile(keyPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyFile.Close()
	return pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

// certCache serves a keypair from disk, reloading it only when the files
// change. The split up/down certificates used to be read and parsed on every
// handshake, which paid two disk reads and a key parse per connection and, in
// the window where a rotation had written the certificate but not yet the key,
// failed the load and silently served the main certificate under the wrong SNI.
type certCache struct {
	certFile string
	keyFile  string

	mu    sync.Mutex
	cert  *tls.Certificate
	stamp [2]fileStamp
}

type fileStamp struct {
	modTime time.Time
	size    int64
}

func newCertCache(certFile, keyFile string) *certCache {
	if certFile == "" || keyFile == "" {
		return nil
	}
	return &certCache{certFile: certFile, keyFile: keyFile}
}

// get returns the current keypair, reloading it when either file has changed.
// A rotation caught mid-write keeps the previously loaded keypair rather than
// failing the handshake; the next connection retries the load.
func (c *certCache) get() (*tls.Certificate, error) {
	stamp := [2]fileStamp{statStamp(c.certFile), statStamp(c.keyFile)}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cert != nil && stamp == c.stamp {
		return c.cert, nil
	}
	cert, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
	if err != nil {
		if c.cert != nil {
			return c.cert, nil
		}
		return nil, err
	}
	c.cert = &cert
	c.stamp = stamp
	return c.cert, nil
}

func statStamp(path string) fileStamp {
	info, err := os.Stat(path)
	if err != nil {
		return fileStamp{}
	}
	return fileStamp{modTime: info.ModTime(), size: info.Size()}
}
