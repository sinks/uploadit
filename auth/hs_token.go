package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"io"
)

var (
	HeaderHS256 = Header{Alg: "HS256", Typ: "JWT"}
	HeaderHS512 = Header{Alg: "HS512", Typ: "JWT"}
)

type HSToken struct {
	header      Header
	hashingFunc func() hash.Hash
	secret      string
}

func TokenHS256(secret string) Token {
	return HSToken{
		header:      HeaderHS256,
		hashingFunc: sha256.New,
		secret:      secret,
	}
}

func TokenHS512(secret string) Token {
	return HSToken{
		header:      HeaderHS512,
		hashingFunc: sha512.New,
		secret:      secret,
	}
}

// Verify a JWS token.
// returns true if  header.payload matches signature, false otherwise.
func (hst HSToken) Verify(token []byte) bool {
	parts := bytes.Split(token, []byte("."))
	if len(parts) != 3 {
		return false
	}
	header := string(parts[0])
	payload := string(parts[1])
	signature := string(parts[2])
	signatureBase64 := base64.RawStdEncoding.EncodeToString(hst.signature(header, payload))
	return signatureBase64 == signature
}

// EncodeToString takes an interface that can be
// marshalled to json.
// It returns a JWS token.
func (hst HSToken) EncodeToString(payload interface{}) string {
	headerBytes, err := json.Marshal(hst.header)
	if err != nil {
		return ""
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	headerBase64 := base64.RawStdEncoding.EncodeToString(headerBytes)
	payloadBase64 := base64.RawStdEncoding.EncodeToString(payloadBytes)
	signatureBase64 := base64.RawStdEncoding.EncodeToString(hst.signature(headerBase64, payloadBase64))
	return fmt.Sprintf("%s.%s.%s", headerBase64, payloadBase64, signatureBase64)
}

func (hst HSToken) signature(header string, payload string) []byte {
	hash := hmac.New(hst.hashingFunc, []byte(hst.secret))
	io.WriteString(hash, fmt.Sprintf("%s.%s", header, payload))
	return hash.Sum(nil)
}
