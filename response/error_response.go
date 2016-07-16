package response

import (
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
