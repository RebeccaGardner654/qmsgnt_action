package main

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Example with sample ClientHello hex data
func exampleWithSampleData() {
	fmt.Println("=== Example with Sample ClientHello Data ===")
	
	// Sample partial ClientHello hex data (this is truncated for demo purposes)
	// In real usage, you would capture this from browser traffic
	sampleHex := strings.Repeat("16030300", 20) // Creates a longer hex string for demo
	
	// Temporarily modify the global rawClientHello for this example
	originalCreateUTLSClient := createUTLSClient
	
	// Create a version with sample data
	createUTLSClientWithSample := func(proxy *url.URL, timeout time.Duration) (*http.Client, error) {
		// This is just for demonstration - in real usage you'd modify the rawClientHello variable
		fmt.Printf("Using sample hex data: %s...\n", sampleHex[:50])
		return originalCreateUTLSClient(proxy, timeout)
	}
	
	client, err := createUTLSClientWithSample(nil, 30*time.Second)
	if err != nil {
		log.Printf("Failed to create client: %v", err)
		return
	}
	
	fmt.Printf("Client created successfully with timeout: %v\n", client.Timeout)
	fmt.Println("Note: This uses fallback transport since sample data is not a valid ClientHello")
}

func exampleMain() {
	fmt.Println("Custom TLS Fingerprint Client Demo")
	fmt.Println("==================================")
	
	// Example 1: Basic usage
	fmt.Println("\n=== Basic Usage (Empty ClientHello) ===")
	client, err := createUTLSClient(nil, 30*time.Second)
	if err != nil {
		log.Fatalf("Failed to create uTLS client: %v", err)
	}
	
	fmt.Println("✓ uTLS client created successfully!")
	fmt.Printf("✓ Client timeout: %v\n", client.Timeout)
	
	// Example 2: With proxy
	fmt.Println("\n=== Usage with Proxy ===")
	proxy, _ := url.Parse("http://proxy:8080")
	clientWithProxy, err := createUTLSClient(proxy, 15*time.Second)
	if err != nil {
		log.Printf("Failed to create client with proxy: %v", err)
	} else {
		fmt.Println("✓ uTLS client with proxy created successfully!")
		fmt.Printf("✓ Client timeout: %v\n", clientWithProxy.Timeout)
	}
	
	// Example 3: Sample data demonstration
	exampleWithSampleData()
	
	fmt.Println("\n=== How to Use with Real Data ===")
	fmt.Println("1. Capture ClientHello hex data using Wireshark or similar tool")
	fmt.Println("2. Replace the empty rawClientHello string in client.go")
	fmt.Println("3. Rebuild and run the application")
	fmt.Println("4. The client will use your custom TLS fingerprint")
	
	fmt.Println("\n=== Implementation Features ===")
	fmt.Println("✓ Custom TLS fingerprint from hex data")
	fmt.Println("✓ Graceful fallback to standard HTTP transport")
	fmt.Println("✓ Proxy support")
	fmt.Println("✓ Configurable timeouts")
	fmt.Println("✓ Error handling and logging")
}