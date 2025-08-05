# Custom TLS Fingerprint Client

This Go application implements a custom TLS client that can use captured ClientHello hex data to create a unique TLS fingerprint, replacing the fixed `utls.HelloChrome_120` fingerprint pattern.

## Features

- **Custom TLS Fingerprint**: Parse captured ClientHello hex data to create unique TLS fingerprints
- **Fallback Mechanism**: Automatically falls back to standard HTTP transport if custom fingerprint parsing fails
- **Proxy Support**: Optional proxy configuration support
- **Error Handling**: Graceful error handling with informative logging
- **Simple API**: Clean, single-function interface for TLS client creation

## Installation

```bash
go mod tidy
go build .
```

## Usage

### Basic Usage

```go
package main

import (
    "net/url"
    "time"
)

func main() {
    // Create client with no proxy and 30-second timeout
    client, err := createUTLSClient(nil, 30*time.Second)
    if err != nil {
        log.Fatal(err)
    }
    
    // Use client for HTTP requests
    resp, err := client.Get("https://example.com")
    // ... handle response
}
```

### With Custom ClientHello Data

To use your own captured ClientHello data, replace the empty `rawClientHello` string in `client.go`:

```go
// In createUTLSClient function
rawClientHello := "160301..." // Replace with your captured hex data
```

### With Proxy

```go
proxy, _ := url.Parse("http://proxy:8080")
client, err := createUTLSClient(proxy, 30*time.Second)
```

## How It Works

1. **Custom Hex Parsing**: The `rawClientHello` hex string is parsed into bytes
2. **TLS Spec Creation**: The bytes are converted into a uTLS ClientHelloSpec
3. **uTLS Client**: A custom transport is created using the parsed specification
4. **Fallback**: If parsing fails at any step, falls back to standard HTTP transport

## Key Functions

- `createUTLSClient(proxy *url.URL, timeout time.Duration)`: Main function to create TLS client
- `parseClientHelloToSpec(clientHelloBytes []byte)`: Converts hex data to TLS specification
- `dialUTLS(network, addr string, spec *utls.ClientHelloSpec)`: Establishes uTLS connection

## Testing

Run the test suite:

```bash
go test -v .
```

## ClientHello Data Capture

To capture your own ClientHello data:

1. Use Wireshark to capture TLS handshake packets
2. Filter for TLS Client Hello messages
3. Export the hex data from the packet payload
4. Replace the `rawClientHello` variable with your data

## Advantages Over Fixed Fingerprints

- **Uniqueness**: Each captured fingerprint is unique to the browser/environment
- **Anti-Detection**: Harder for anti-bot systems to detect compared to standard uTLS patterns
- **Flexibility**: Easy to update with new captured data
- **Fallback Safety**: Graceful degradation if custom fingerprint fails

## Dependencies

- `github.com/refraction-networking/utls`: For custom TLS fingerprinting
- Go standard library packages for networking and crypto operations

## License

This project follows the same license as the parent repository.