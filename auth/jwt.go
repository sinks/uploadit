package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

var (
	HeaderHS256 = Header{Alg: "HS256", Typ: "JWT"}
)

type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type JWT struct {
	Header  Header
	Payload interface{}
}

func (jwt JWT) Encode(secret string) string {
	headerBytes, err := json.Marshal(jwt.Header)
	if err != nil {
		return ""
	}
	payloadBytes, err := json.Marshal(jwt.Payload)
	if err != nil {
		return ""
	}
	header := base64.RawStdEncoding.EncodeToString(headerBytes)
	payload := base64.RawStdEncoding.EncodeToString(payloadBytes)
	content := Content(header, payload)
	signature := Signature(header, payload, secret)
	return fmt.Sprintf("%s.%s", content, signature)
}

func MarshalJWT(p interface{}) (JWT, error) {
	return JWT{Header: HeaderHS256, Payload: p}, nil
}

// Verify take a jwt token of the form header.payload.signature
// it takes the header.payload and creates a signature
// it then compares that signature to the signature portion of the
// token
// returns true if a match, false otherwise
func Verify(token []byte, secret string) bool {
	parts := bytes.Split(token, []byte("."))
	if len(parts) != 3 {
		return false
	}
	header := string(parts[0])
	payload := string(parts[1])
	signature := string(parts[2])

	return Signature(header, payload, secret) == signature
}

// Signature takes the base64 encoded version of header and payload
// and uses the SECRET to encode them using hmac sha256
func Signature(header string, payload string, secret string) string {
	hash := hmac.New(sha256.New, []byte(secret))
	hash.Write([]byte(Content(header, payload)))
	return base64.RawStdEncoding.EncodeToString(hash.Sum(nil))
}

// Content takes the base64 encoded header and payload and combines them
func Content(header string, payload string) string {
	return fmt.Sprintf("%s.%s", header, payload)
}
