package main

import (
	"net/url"
	"testing"
	"time"
)

func TestCreateUTLSClient(t *testing.T) {
	tests := []struct {
		name          string
		proxy         *url.URL
		timeout       time.Duration
		expectError   bool
		description   string
	}{
		{
			name:        "basic client creation",
			proxy:       nil,
			timeout:     30 * time.Second,
			expectError: false,
			description: "Should create client successfully with no proxy",
		},
		{
			name:        "client with proxy",
			proxy:       mustParseURL("http://proxy:8080"),
			timeout:     10 * time.Second,
			expectError: false,
			description: "Should create client successfully with proxy",
		},
		{
			name:        "client with zero timeout",
			proxy:       nil,
			timeout:     0,
			expectError: false,
			description: "Should create client successfully with zero timeout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := createUTLSClient(tt.proxy, tt.timeout)
			
			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
				return
			}
			
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			
			if !tt.expectError {
				if client == nil {
					t.Errorf("Expected client but got nil")
					return
				}
				
				if client.Timeout != tt.timeout {
					t.Errorf("Expected timeout %v, got %v", tt.timeout, client.Timeout)
				}
			}
		})
	}
}

func TestParseClientHelloToSpec(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		expectError bool
		description string
	}{
		{
			name:        "empty data",
			data:        []byte{},
			expectError: true,
			description: "Should fail with empty ClientHello data",
		},
		{
			name:        "too short data",
			data:        make([]byte, 10),
			expectError: true,
			description: "Should fail with too short ClientHello data",
		},
		{
			name:        "minimum valid data",
			data:        make([]byte, 50), // Create 50 bytes of dummy data
			expectError: false,
			description: "Should succeed with minimum valid ClientHello data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := parseClientHelloToSpec(tt.data)
			
			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
				return
			}
			
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			
			if !tt.expectError && spec == nil {
				t.Errorf("Expected spec but got nil")
			}
		})
	}
}

func TestGetHostFromAddr(t *testing.T) {
	tests := []struct {
		addr     string
		expected string
	}{
		{"example.com:443", "example.com"},
		{"192.168.1.1:8080", "192.168.1.1"},
		{"[::1]:443", "::1"},
		{"invalid", "invalid"},
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			result := getHostFromAddr(tt.addr)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

// Helper function for tests
func mustParseURL(rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	return u
}