package auth

type Token interface {
	Verify(token []byte) bool
	EncodeToString(payload interface{}) string
}

type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}
