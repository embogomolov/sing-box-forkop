package tls

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestSelfSignedCertificateIsItsOwnIssuer(t *testing.T) {
	_, certificatePem, err := GenerateCertificate(nil, nil, time.Now, "vpn.example.com", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certificatePem)
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatalf("CA %v, key usage %b: not usable as its own issuer", certificate.IsCA, certificate.KeyUsage)
	}
	// OpenVPN's remote-cert-tls server requires a key usage and the server auth purpose.
	if certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
		len(certificate.ExtKeyUsage) != 1 || certificate.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("key usage %b, extended %v", certificate.KeyUsage, certificate.ExtKeyUsage)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	if _, err = certificate.Verify(x509.VerifyOptions{DNSName: "vpn.example.com", Roots: roots}); err != nil {
		t.Fatal(err)
	}
}
