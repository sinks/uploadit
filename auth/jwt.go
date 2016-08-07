package auth

type Token interface {
	Verify(token []byte) bool
	Encode(payload interface{}) (string, error)
}

type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}
