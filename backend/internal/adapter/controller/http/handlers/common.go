package handlers

import (
	"encoding/json"
	"net/http"
)

// JSONResponse sends a JSON response with the given status code
func JSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}

// ErrorResponse sends a JSON error response
func ErrorResponse(w http.ResponseWriter, statusCode int, message string, err error) {
	response := map[string]interface{}{
		"error":   message,
		"success": false,
	}
	if err != nil {
		response["details"] = err.Error()
	}
	JSONResponse(w, statusCode, response)
}

// SuccessResponse sends a JSON success response
func SuccessResponse(w http.ResponseWriter, message string, data interface{}) {
	response := map[string]interface{}{
		"message": message,
		"success": true,
	}
	if data != nil {
		response["data"] = data
	}
	JSONResponse(w, http.StatusOK, response)
}

// DecodeJSON decodes JSON from request body
func DecodeJSON(r *http.Request, v interface{}) error {
	return json.NewDecoder(r.Body).Decode(v)
}

// PaginatedResponse represents a paginated API response
type PaginatedResponse struct {
	Data       interface{} `json:"data"`
	Pagination Pagination  `json:"pagination"`
}

// Pagination contains pagination metadata
type Pagination struct {
	Total   int64 `json:"total"`
	Limit   int   `json:"limit"`
	Offset  int   `json:"offset"`
	HasMore bool  `json:"has_more"`
}

// NewPaginatedResponse creates a new paginated response
func NewPaginatedResponse(data interface{}, total int64, limit, offset int) *PaginatedResponse {
	return &PaginatedResponse{
		Data: data,
		Pagination: Pagination{
			Total:   total,
			Limit:   limit,
			Offset:  offset,
			HasMore: int64(offset+limit) < total,
		},
	}
}
