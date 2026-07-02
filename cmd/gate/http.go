package main

import (
	"fmt"
	"io"
	"net/http"
)

func readLimited(r *http.Request, limit int64) ([]byte, error) {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read request body: %w", err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("request body too large")
	}
	return body, nil
}
