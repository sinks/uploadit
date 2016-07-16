package auth

import (
	"testing"
)

var (
	ExpectedEncode = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
)

type TestJSONMarshal struct {
	Sub   string `json:"sub"`
	Name  string `json:"name"`
	Admin bool   `json:"admin"`
}

func TestEncode(t *testing.T) {
	payload := TestJSONMarshal{Sub: "1234567890", Name: "John Doe", Admin: true}
	jwt, err := MarshalJWT(payload)
	if err != nil {
		t.Error("Expected to marshal test struct")
	}
	encode := jwt.Encode()
	if encode != ExpectedEncode {
		t.Error("Encodeing is invalid", encode)
	}
}
