package main

import (
	"encoding/json"
	"errors"
	"github.com/julienschmidt/httprouter"
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
	router := httprouter.New()
	router.POST("/uploads/:id", handleNewUpload)
	router.POST("/token", handleTokenGeneration)
	http.ListenAndServe(":8080", router)
}

func errHandleFunc(w http.ResponseWriter, r *http.Request, response response.ErrorResponse) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(response.Status)
	encErr := json.NewEncoder(w).Encode(response)
	if encErr != nil {
		http.Error(w, encErr.Error(), http.StatusInternalServerError)
	}
	return
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
		errHandleFunc(w, r, response.UnauthorizedRequest)
		return
	}
	uploadId, err := checkToken(r, p)
	if err != nil {
		errHandleFunc(w, r, response.BadRequest)
		return
	}
	u := Upload{Id: uploadId}
	err = u.Handle(w, r)
	if err != nil {
		errHandleFunc(w, r, response.BadRequest)
		return
	}
}
