package auth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
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
	header      Header
	hashingFunc func() hash.Hash
	hash        crypto.Hash
	priv        rsa.PrivateKey
}

func TokenRS256(priv rsa.PrivateKey) Token {
	return RSToken{
		header:      HeaderRS256,
		hashingFunc: sha256.New,
		hash:        crypto.SHA256,
		priv:        priv,
	}
}

func (rst RSToken) Verify(token []byte) bool {
	return false
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
	headerBase64 := base64.RawStdEncoding.EncodeToString(headerBytes)
	payloadBase64 := base64.RawStdEncoding.EncodeToString(payloadBytes)
	signature, err := rst.signature(headerBase64, payloadBase64)
	if err != nil {
		return "", err
	}
	signatureBase64 := base64.RawStdEncoding.EncodeToString(signature)
	return fmt.Sprintf("%s.%s.%s", headerBase64, payloadBase64, signatureBase64), nil
}

func (rst RSToken) signature(header string, payload string) ([]byte, error) {
	hash := rst.hashingFunc()
	io.WriteString(hash, fmt.Sprintf("%s.%s", header, payload))
	content := hash.Sum(nil)
	signature, err := rsa.SignPKCS1v15(rng, &rst.priv, rst.hash, content)
	if err != nil {
		return nil, err
	}
	return signature, nil
}
