package auth

import (
	"encoding/json"
	"github.com/julienschmidt/httprouter"
	"net/http"
)

var (
	Users = []User{
		User{Name: "lincoln"},
		User{Name: "abe"},
	}
	Logins = []Login{
		Login{Identity: "lincoln", Password: "abc123", User: Users[0]},
	}
)

type User struct {
	Name string `json:"name"`
}

type Login struct {
	Identity string
	Password string
	User     User
}

func verify(username string, password string) (User, bool) {
	for _, value := range Logins {
		if value.Identity == username &&
			value.Password == password {
			return value.User, true
		}
	}
	return User{}, false
}

type LoginResponse struct {
	Token string `json:"token"`
}

func HandleLogin(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	username, password, _ := r.BasicAuth()
	if user, ok := verify(username, password); ok {
		token, _ := MarshalJWT(user)
		response := LoginResponse{Token: token.Encode()}
		w.Header().Add("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}
