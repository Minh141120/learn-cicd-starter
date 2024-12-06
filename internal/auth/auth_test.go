package auth

import (
	"net/http"
	"strings"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
		errorContains string
	}{
		{
			name: "valid API key",
			headers: http.Header{
				"Authorization": []string{"ApiKey test-key-123"},
			},
			expectedKey:   "test-key-123",
			expectedError: nil,
		},
		{
			name:          "missing authorization header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "malformed header - wrong format",
			headers: http.Header{
				"Authorization": []string{"Bearer test-key-123"},
			},
			expectedKey:   "",
			errorContains: "malformed authorization header",
		},
		{
			name: "malformed header - missing key",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey:   "",
			errorContains: "malformed authorization header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			// Check if we got the expected key
			if key != tt.expectedKey {
				t.Errorf("expected key %q, got %q", tt.expectedKey, key)
			}

			// Check error cases
			if tt.expectedError != nil && err != tt.expectedError {
				t.Errorf("expected error %v, got %v", tt.expectedError, err)
			}

			if tt.errorContains != "" && (err == nil || !strings.Contains(err.Error(), tt.errorContains)) {
				t.Errorf("expected error containing %q, got %v", tt.errorContains, err)
			}
		})
	}
}
