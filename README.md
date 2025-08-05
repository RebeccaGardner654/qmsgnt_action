# QmsgNT Action - TLS Fingerprint Implementation

This application implements TLS fingerprinting using captured ClientHello packet data to replace fixed TLS fingerprints.

## Features

- **Custom TLS Fingerprinting**: Uses real captured ClientHello data instead of fixed `utls.HelloChrome_120`
- **Hex Data Decoding**: Decodes the raw hex packet data and extracts TLS handshake records
- **UTLS Integration**: Uses `github.com/refraction-networking/utls` for TLS fingerprinting
- **Error Handling**: Falls back to standard HTTP when custom TLS fails
- **Comprehensive Logging**: Detailed logging for debugging TLS connections

## Usage

```bash
# Build the application
go build -o qmsgnt_action main.go

# Run the application
./qmsgnt_action
```

## Implementation Details

The application:

1. **Decodes hex ClientHello data** - The raw packet data is stored as a hex string constant
2. **Extracts TLS handshake record** - Skips protocol headers to find the TLS handshake at offset 44
3. **Creates custom fingerprint** - Uses `utls.Fingerprinter` to parse the ClientHello and extract:
   - 16 cipher suites
   - 18 TLS extensions
   - TLS version and other parameters
4. **Establishes TLS connections** - Creates HTTP client with custom TLS transport using the fingerprint
5. **Handles failures gracefully** - Falls back to standard HTTP if custom TLS fails

## Testing

Run the test suite to verify the implementation:

```bash
go test -v
```

Tests cover:
- ClientHello data parsing and validation
- TLS fingerprint creation
- HTTP client setup with custom TLS
- Fallback mechanism
- Integration testing

## Raw ClientHello Data

The application uses real captured ClientHello data containing:
- TLS 1.3 and 1.2 support
- Modern cipher suites (ChaCha20, AES-GCM, etc.)
- SNI and ALPN extensions
- Key exchange groups (X25519, P-256, P-384)
- Signature algorithms

This provides a realistic TLS fingerprint that mimics actual browser behavior.