package auth

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
)

var (
	HeaderRS256 = Header{Alg: "RS256", Typ: "JWT"}
	HeaderRS512 = Header{Alg: "RS512", Typ: "JWT"}
)

var (
	rng = rand.Reader
)

type RSToken struct {
	header Header
	hash   crypto.Hash
	priv   rsa.PrivateKey
}

func TokenRS256(priv rsa.PrivateKey) Token {
	return RSToken{
		header: HeaderRS256,
		hash:   crypto.SHA256,
		priv:   priv,
	}
}

func (rst RSToken) Verify(token []byte) bool {
	parts := bytes.Split(token, []byte("."))
	if len(parts) != 3 {
		return false
	}
	header := string(parts[0])
	payload := string(parts[1])
	signature := string(parts[2])
	computedSignature, err := rst.signature(header, payload)
	if err != nil {
		return false
	}
	signatureComputedBase64 := base64.RawURLEncoding.EncodeToString(computedSignature)
	return signature == signatureComputedBase64
}

func (rst RSToken) Encode(payload interface{}) (string, error) {
	headerBytes, err := json.Marshal(rst.header)
	if err != nil {
		return "", err
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	headerBase64 := base64.RawURLEncoding.EncodeToString(headerBytes)
	payloadBase64 := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signature, err := rst.signature(headerBase64, payloadBase64)
	if err != nil {
		return "", err
	}
	signatureBase64 := base64.RawURLEncoding.EncodeToString(signature)
	return fmt.Sprintf("%s.%s.%s", headerBase64, payloadBase64, signatureBase64), nil
}

func (rst RSToken) signature(header string, payload string) ([]byte, error) {
	hashInstance := rst.hash.New()
	io.WriteString(hashInstance, fmt.Sprintf("%s.%s", header, payload))
	content := hashInstance.Sum(nil)
	signature, err := rsa.SignPKCS1v15(rng, &rst.priv, rst.hash, content)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func LoadFromPublicPem(block []byte) *rsa.PublicKey {
	b, _ := pem.Decode(block)
	var cert *x509.Certificate
	cert, _ = x509.ParseCertificate(b.Bytes)
	rsaPublicKey := cert.PublicKey.(*rsa.PublicKey)
	return rsaPublicKey
}

func LoadFromPrivatePem(block []byte) *rsa.PrivateKey {
	b, _ := pem.Decode(block)
	cert, _ := x509.ParsePKCS1PrivateKey(b.Bytes)
	return cert
}
