package types

import (
	"fmt"
	"strings"
)

type APIEnvelope[T any] struct {
	Data  T         `json:"data,omitempty"`
	Error *APIError `json:"error,omitempty"`
	OK    bool      `json:"ok"`
}

type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type APIRequestError struct {
	StatusCode int    `json:"-"`
	Code       string `json:"code,omitempty"`
	Message    string `json:"message,omitempty"`
}

func (e *APIRequestError) Error() string {
	if e == nil {
		return ""
	}
	code := strings.TrimSpace(e.Code)
	message := strings.TrimSpace(e.Message)
	if code != "" {
		return code + ": " + message
	}
	if message != "" {
		return message
	}
	if e.StatusCode > 0 {
		return fmt.Sprintf("api request failed with status %d", e.StatusCode)
	}
	return "api request failed"
}

func (e *APIRequestError) Is(target error) bool {
	other, ok := target.(*APIRequestError)
	if !ok {
		return false
	}
	if other.Code != "" && e.Code != other.Code {
		return false
	}
	if other.StatusCode != 0 && e.StatusCode != other.StatusCode {
		return false
	}
	return true
}
