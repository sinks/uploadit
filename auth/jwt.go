package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

const (
	SECRET = "secret"
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
	Payload []byte
}

func (jwt JWT) Encode() string {
	headerBytes, err := json.Marshal(jwt.Header)
	if err != nil {
		return ""
	}
	header := base64.RawStdEncoding.EncodeToString(headerBytes)
	payload := base64.RawStdEncoding.EncodeToString(jwt.Payload)
	content := fmt.Sprintf("%s.%s", header, payload)
	hash := hmac.New(sha256.New, []byte(SECRET))
	hash.Write([]byte(content))
	signature := base64.RawStdEncoding.EncodeToString(hash.Sum(nil))
	return fmt.Sprintf("%s.%s", content, signature)
}

func MarshalJWT(payload interface{}) (JWT, error) {
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return JWT{}, err
	}
	return JWT{Header: HeaderHS256, Payload: payloadJSON}, nil
}
