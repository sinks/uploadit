package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/julienschmidt/httprouter"
	"github.com/twinj/uuid"
	"net/http"
	"sync"
	"time"
)

const (
	EXPIRY_MIN      = 1 * time.Minute
	EXPIRY_DURATION = time.Duration(EXPIRY_MIN)
)

var (
	TokenNotFound = errors.New("Token Not Found")
	TokenInvalid  = errors.New("Token Invalid")
)

type TokenEntry struct {
	Id     uuid.Uuid `json:"id"`
	Expiry time.Time `json:"expiry"`
}

type TokenTable struct {
	tokens map[string]TokenEntry
	lock   sync.RWMutex
}

func (tt *TokenTable) Init() {
	tt.tokens = make(map[string]TokenEntry)
}

func (tt *TokenTable) Add(uuid uuid.Uuid) TokenEntry {
	tt.lock.Lock()
	entry := tt.add(uuid)
	tt.lock.Unlock()
	return entry
}

func (tt *TokenTable) Remove(uuid uuid.Uuid) {
	tt.lock.Lock()
	tt.remove(uuid)
	tt.lock.Unlock()
}

func (tt *TokenTable) Sweep() {
	tt.lock.Lock()
	for _, entry := range tt.tokens {
		now := time.Now()
		markToClean := now.After(entry.Expiry)
		if markToClean {
			tt.remove(entry.Id)
		}
	}
	tt.lock.Unlock()
}

func (tt *TokenTable) HasValidToken(id uuid.Uuid) bool {
	tt.lock.RLock()
	isValid := tt.hasValidToken(id)
	tt.lock.RUnlock()
	return isValid
}

func (tt *TokenTable) Use(id uuid.Uuid) (uuid.Uuid, error) {
	tt.lock.Lock()
	defer tt.lock.Unlock()
	if !tt.hasValidToken(id) {
		return nil, errors.New("Invalid token")
	}
	tt.remove(id)
	return id, nil
}

func (tt *TokenTable) hasValidToken(id uuid.Uuid) bool {
	entry, ok := tt.tokens[id.String()]
	if ok {
		now := time.Now()
		if now.Before(entry.Expiry) {
			return true
		}
	}
	return false
}

func (tt *TokenTable) add(uuid uuid.Uuid) TokenEntry {
	expiry := time.Now().Add(EXPIRY_DURATION)
	entry := TokenEntry{Id: uuid, Expiry: expiry}
	tt.tokens[uuid.String()] = TokenEntry{Id: uuid, Expiry: expiry}
	return entry
}

func (tt *TokenTable) remove(uuid uuid.Uuid) {
	fmt.Println("Remove", uuid.String())
	delete(tt.tokens, uuid.String())
}

var (
	Tokens TokenTable
)

func UploadSweeper() {
	for {
		Tokens.Sweep()
		time.Sleep(15 * time.Second)
	}
}

func handleTokenGeneration(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	entry := Tokens.Add(uuid.NewV1())
	w.Header().Add("Content-Type", "application/json")
	encErr := json.NewEncoder(w).Encode(entry)
	if encErr != nil {
		http.Error(w, encErr.Error(), http.StatusInternalServerError)
	}
}
