package main

// based on https://golang.org/src/crypto/tls/generate_cert.go

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/miekg/dns"
	"log"
	"math/big"
	"os"
	"strings"
	"time"
)


func main() {
	flag.Parse()

	if len(os.Args) < 2 {
		log.Fatalf("Missing required host")
	}

	host := strings.TrimSpace(os.Args[1])
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	keyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment

	var notBefore time.Time
	notBefore = time.Now()
	notAfter := notBefore.Add(365*24*time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}

	wildcardHost := "*." + host
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: wildcardHost,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	template.DNSNames = append(template.DNSNames, host)
	template.DNSNames = append(template.DNSNames, wildcardHost)

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	certOut, err := os.Create("cert.pem")
	if err != nil {
		log.Fatalf("Failed to open cert.pem for writing: %v", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		log.Fatalf("Failed to write data to cert.pem: %v", err)
	}
	if err := certOut.Close(); err != nil {
		log.Fatalf("Error closing cert.pem: %v", err)
	}


	keyOut, err := os.OpenFile("key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Failed to open key.pem for writing: %v", err)
		return
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		log.Fatalf("Unable to marshal private key: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		log.Fatalf("Failed to write data to key.pem: %v", err)
	}
	if err := keyOut.Close(); err != nil {
		log.Fatalf("Error closing key.pem: %v", err)
	}
	fmt.Println("Generated self-signed certificate: cert.pem, cert.key")

	x509cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		log.Fatalf("Failed to parse certificate: %v", err)
	}

	hash, err := dns.CertificateToDANE(1,1, x509cert)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("TLSA Record data: 3 1 1", hash)
}