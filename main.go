package main

import (
	"errors"
	"github.com/julienschmidt/httprouter"
	"github.com/sinks/uploadit/auth"
	"github.com/sinks/uploadit/response"
	"github.com/twinj/uuid"
	"net/http"
	"time"
)

type UploadEntry struct {
	Id     uuid.Uuid
	Expiry time.Time
}

var (
	Uploads map[string]UploadEntry
)

func main() {
	uuid.Init()
	Tokens.Init()
	go UploadSweeper()
	routerUploads := httprouter.New()
	routerUploads.POST("/uploads/:id", handleNewUpload)
	routerUploads.POST("/token", handleTokenGeneration)
	go http.ListenAndServe(":8080", routerUploads)
	routerLogin := httprouter.New()
	routerLogin.POST("/login", auth.HandleLogin)
	http.ListenAndServe(":8081", routerLogin)
}

func checkToken(r *http.Request, p httprouter.Params) (uuid.Uuid, error) {
	uploadUuid, err := uuid.Parse(p.ByName("id"))
	if err != nil {
		return nil, TokenInvalid
	}
	uuid, err := Tokens.Use(uploadUuid)
	return uuid, err
}

func checkAuth(r *http.Request, p httprouter.Params) error {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return errors.New("No Authorization header")
	}
	return nil
}

func handleNewUpload(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	err := checkAuth(r, p)
	if err != nil {
		response.ErrHandleFunc(w, r, response.UnauthorizedRequest)
		return
	}
	uploadId, err := checkToken(r, p)
	if err != nil {
		response.ErrHandleFunc(w, r, response.BadRequest)
		return
	}
	u := Upload{Id: uploadId}
	err = u.Handle(w, r)
	if err != nil {
		response.ErrHandleFunc(w, r, response.BadRequest)
		return
	}
}
