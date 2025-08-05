# Sample ClientHello Hex Data

This file contains examples of what real ClientHello hex data looks like when captured from browser traffic.

## Example 1: Chrome ClientHello (Truncated)
```
160301020a010002060303f8a5d4e4c8b5b3c8d0a5f9e4c2d1b7a8e9f3c4d5b6a7e8f9a0b1c2d3e4f5a6b7c8d9eaf0b1c2d3e4f5a6b7c8d9
```

## Example 2: Firefox ClientHello (Truncated)
```
160301020901000205030362f8a5d4e4c8b5b3c8d0a5f9e4c2d1b7a8e9f3c4d5b6a7e8f9a0b1c2d3e4f5a6b7c8d9eaf0b1c2d3e4f5a6
```

## How to Capture Real Data

### Using Wireshark:
1. Start packet capture on your network interface
2. Filter for TLS traffic: `tls.handshake.type == 1`
3. Navigate to a website in your browser
4. Find the Client Hello packet
5. Right-click → Copy → Bytes → Hex Stream
6. Paste the hex string into the `rawClientHello` variable

### Using Browser DevTools:
1. Open Chrome DevTools → Security tab
2. Navigate to a HTTPS site
3. Look for TLS handshake details
4. Some browsers provide hex dump in connection info

### Using curl with verbose output:
```bash
curl -v --tls-max 1.3 --tlsv1.2 https://example.com
```

## Important Notes:

- Remove spaces and newlines from hex data
- Ensure the hex string represents a complete ClientHello message
- The data should start with the TLS record header (typically 16 03 xx)
- Different browsers create different fingerprints
- Modern browsers use TLS 1.3 with randomized extensions

## Usage in Code:

Replace the empty string in `client.go`:
```go
rawClientHello := "160301020a010002060303f8a5d4e4c8b5b3c8d0a5f9..." // Your captured data here
```