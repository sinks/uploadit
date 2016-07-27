package response

import (
	"encoding/json"
	"net/http"
)

var (
	BadRequest          = ErrorResponse{Message: "Bad Request", Status: http.StatusBadRequest}
	UnauthorizedRequest = ErrorResponse{Message: "Unauthorized", Status: http.StatusUnauthorized}
)

type ErrorResponse struct {
	Status  int    `json:"status"`
	Message string `json:"error"`
}

func (er ErrorResponse) Error() string {
	return er.Message
}

func ErrHandleFunc(w http.ResponseWriter, r *http.Request, response ErrorResponse) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(response.Status)
	encErr := json.NewEncoder(w).Encode(response)
	if encErr != nil {
		http.Error(w, encErr.Error(), http.StatusInternalServerError)
	}
	return
}
