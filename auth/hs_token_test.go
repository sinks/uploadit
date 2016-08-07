package auth

import (
	"testing"
)

type TestJSONMarshal struct {
	Sub   string `json:"sub"`
	Name  string `json:"name"`
	Admin bool   `json:"admin"`
}

func TestHS256EncodeToString(t *testing.T) {
	// {"alg": "HS256", "typ": "JWT"}
	// {"sub": "1234567890", "name": "John Doe", "admin": true}
	// secret: secret
	AdminToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
	payload := TestJSONMarshal{Sub: "1234567890", Name: "John Doe", Admin: true}
	tokenizer := TokenHS256("secret")
	encode := tokenizer.EncodeToString(payload)
	if encode != AdminToken {
		t.Error("Encodeing is invalid", encode)
	}
}

func TestHS256Verify(t *testing.T) {
	// {"alg": "HS256", "typ": "JWT"}
	// {"sub": "1234567890", "name": "John Doe", "admin": true}
	// secret: secret
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
	tokenizer := TokenHS256("secret")
	isVerified := tokenizer.Verify([]byte(token))
	if !isVerified {
		t.Error("Couldnt verify jwt")
	}
}

func TestHS256VerifyWithWrongSecret(t *testing.T) {
	// {"alg": "HS256", "typ": "JWT"}
	// {"sub": "1234567890", "name": "John Doe", "admin": true}
	// secret: bad
	badToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.ew7bOxVUA9ZA1ABBHu+NHtvd08+KvU+sV4wXmYOF0+4"
	tokenizer := TokenHS256("secret")
	isVerified := tokenizer.Verify([]byte(badToken))
	if isVerified {
		t.Error("Token with verified with invalid secret")
	}
}

func TestHS256VerifyWithWrongPayloadInSignature(t *testing.T) {
	// {"alg": "HS256", "typ": "JWT"}
	// {"sub": "1234567890", "name": "John Doe", "admin": true}
	// secret: has a changed payload of name: "Abe Top"
	badToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.kpY7JmzUDFXhjmbCM4a2WzZl4DpqsV_ruyE3sI63Yc8"
	tokenizer := TokenHS256("secret")
	isVerified := tokenizer.Verify([]byte(badToken))
	if isVerified {
		t.Error("Token with verified with invalid secret")
	}
}
