package main

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
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

type RootCA struct {
	DirName    string
	FileName   string
	CommonName string
	Country    string
	Province   string
	Locality   string
	Password   string
	Duration   time.Duration
	ForceRSA   bool

	once sync.Once
	ca   *x509.Certificate
	priv interface{}
}

func (ca *RootCA) ext() string {
	if s := filepath.Ext(ca.FileName); s != "" {
		return s
	}
	return ".pem"
}

func (ca *RootCA) init() error {
	if _, err := os.Stat(ca.DirName); os.IsNotExist(err) {
		os.Mkdir(ca.DirName, 0755)
		if ca.Password != "" {
			os.WriteFile(filepath.Join(ca.DirName, "readme.txt"), []byte(`The password of pfx files is 123456`), 0644)
		}
	}

	rootFile := filepath.Join(ca.DirName, ca.FileName)

	if _, err := os.Stat(rootFile); os.IsNotExist(err) {
		template := x509.Certificate{
			IsCA:         true,
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName:   ca.CommonName,
				Country:      []string{ca.Country},
				Province:     []string{ca.Province},
				Locality:     []string{ca.Locality},
				Organization: []string{ca.CommonName},
				ExtraNames: []pkix.AttributeTypeAndValue{
					{
						Type:  []int{2, 5, 4, 42},
						Value: ca.CommonName,
					},
				},
			},
			DNSNames: []string{ca.CommonName},

			NotBefore: timeNow().Add(-time.Duration(30 * 24 * time.Hour)),
			NotAfter:  timeNow().Add(ca.Duration),

			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			BasicConstraintsValid: true,
		}

		var b bytes.Buffer
		if ca.ForceRSA {
			priv, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				return err
			}
			der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
			if err != nil {
				return err
			}
			privBytes := x509.MarshalPKCS1PrivateKey(priv)

			pem.Encode(&b, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
			pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: der})
		} else {
			priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return err
			}
			der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
			if err != nil {
				return err
			}
			privBytes, err := x509.MarshalECPrivateKey(priv)
			if err != nil {
				return err
			}

			pem.Encode(&b, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})
			pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: der})
		}

		err = os.WriteFile(rootFile, b.Bytes(), 0644)
		if err != nil {
			return err
		}
	}

	data, err := os.ReadFile(rootFile)
	if err != nil {
		return err
	}

	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			break
		}
		switch b.Type {
		case "CERTIFICATE":
			ca.ca, err = x509.ParseCertificate(b.Bytes)
		case "EC PRIVATE KEY":
			ca.priv, err = x509.ParseECPrivateKey(b.Bytes)
		case "PRIVATE KEY", "PRIVATE RSA KEY":
			ca.priv, err = x509.ParsePKCS1PrivateKey(b.Bytes)
		default:
			err = fmt.Errorf("unsupported %#v certificate, name=%#v", b.Type, ca.CommonName)
		}
		if err != nil {
			return err
		}
	}

	return nil
}

func (ca *RootCA) RootCertificate() *x509.Certificate {
	ca.once.Do(func() { ca.init() })
	return ca.ca
}

func (ca *RootCA) Issue(commonName string) error {
	ca.once.Do(func() { ca.init() })

	csrTemplate := &x509.CertificateRequest{
		Signature: []byte(commonName),
		Subject: pkix.Name{
			Country:            []string{ca.Country},
			Organization:       []string{commonName},
			OrganizationalUnit: []string{ca.CommonName},
			CommonName:         commonName,
		},
		DNSNames: []string{commonName},
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, ca.priv)
	if err != nil {
		return err
	}

	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return err
	}

	certTemplate := &x509.Certificate{
		Subject:            csr.Subject,
		DNSNames:           []string{commonName},
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,
		SerialNumber:       big.NewInt(timeNow().UnixNano()),
		NotBefore:          timeNow().Add(-time.Duration(30 * 24 * time.Hour)),
		NotAfter:           timeNow().Add(ca.Duration),
		KeyUsage:           x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, ca.ca, csr.PublicKey, ca.priv)
	if err != nil {
		return err
	}

	var b bytes.Buffer
	if ca.ForceRSA {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}
		privBytes := x509.MarshalPKCS1PrivateKey(priv)
		pem.Encode(&b, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
		pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	} else {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		privBytes, err := x509.MarshalECPrivateKey(priv)
		if err != nil {
			return err
		}
		pem.Encode(&b, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})
		pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	}

	err = os.WriteFile(filepath.Join(ca.DirName, commonName+ca.ext()), b.Bytes(), 0644)
	if err != nil {
		return err
	}

	return nil
}

func (ca *RootCA) Export(commonName, password string) error {
	cmd := exec.CommandContext(context.Background(),
		"openssl", "pkcs12", "-export",
		"-out", commonName+".pfx",
		"-inkey", ca.FileName,
		"-in", commonName+ca.ext(),
		"-certfile", commonName+ca.ext(),
		"-password", "pass:"+password)
	cmd.Dir = ca.DirName
	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}

func (ca *RootCA) Issused(commonName string) bool {
	_, err := os.Stat(filepath.Join(ca.DirName, commonName+ca.ext()))
	return err == nil
}

func (ca *RootCA) Exported(commonName string) bool {
	_, err := os.Stat(filepath.Join(ca.DirName, commonName+".pfx"))
	return err == nil
}

func GenerateTLSConfig() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(0x7FFFFFFFFFFFFFFF))
	if err != nil {
		return nil, err
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		NotBefore:    time.Now().Add(-30 * 24 * time.Hour),
		NotAfter:     time.Now().Add(360 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type: "EC PRIVATE KEY", Bytes: keyBytes,
	})
	b := pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	certPEM := pem.EncodeToMemory(&b)

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}, nil
}
