package auth

import (
    "net/http"
    "testing"
)

func TestGetAPIKey(t *testing.T) {
    // Case 1: No Authorization header
    headers := http.Header{}
    _, err := GetAPIKey(headers)
    if err != ErrNoAuthHeaderIncluded {
        t.Errorf("expected error %v, got %v", ErrNoAuthHeaderIncluded, err)
    }

    // Case 2: Malformed Authorization header
    headers = http.Header{
        "Authorization": []string{"Bearer sometoken"},
    }
    _, err = GetAPIKey(headers)
    if err == nil || err.Error() != "malformed authorization header" {
        t.Errorf("expected 'malformed authorization header' error, got %v", err)
    }

    // Case 3: Correct Authorization header
    headers = http.Header{
        "Authorization": []string{"ApiKey my-secret-key"},
    }
    apiKey, err := GetAPIKey(headers)
    if err != nil {
        t.Errorf("unexpected error: %v", err)
    }
    if apiKey != "my-secret-key" {
        t.Errorf("expected apiKey 'my-secret-key', got '%s'", apiKey)
    }
}
