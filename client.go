package main

import (
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"

	utls "github.com/refraction-networking/utls"
)

// createUTLSClient creates an HTTP client with custom TLS fingerprint from hex data
func createUTLSClient(proxy *url.URL, timeout time.Duration) (*http.Client, error) {
	// Custom ClientHello hex data - replace with actual captured data
	rawClientHello := "" // 替换为实际数据
	
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	
	// If proxy is provided, configure it
	if proxy != nil {
		transport.Proxy = http.ProxyURL(proxy)
	}
	
	// If rawClientHello is empty, return standard client with fallback
	if rawClientHello == "" {
		log.Println("Warning: No custom ClientHello data provided, using standard transport")
		return &http.Client{
			Transport: transport,
			Timeout:   timeout,
		}, nil
	}
	
	// Parse hex data
	clientHelloBytes, err := hex.DecodeString(rawClientHello)
	if err != nil {
		log.Printf("Warning: Failed to parse ClientHello hex data: %v, falling back to standard transport", err)
		return &http.Client{
			Transport: transport,
			Timeout:   timeout,
		}, nil
	}
	
	// Create custom TLS specification from hex data
	customSpec, err := parseClientHelloToSpec(clientHelloBytes)
	if err != nil {
		log.Printf("Warning: Failed to create custom TLS spec: %v, falling back to standard transport", err)
		return &http.Client{
			Transport: transport,
			Timeout:   timeout,
		}, nil
	}
	
	// Create uTLS transport with custom fingerprint
	utlsTransport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	
	if proxy != nil {
		utlsTransport.Proxy = http.ProxyURL(proxy)
	}
	
	// Override the DialTLS function to use uTLS with custom spec
	utlsTransport.DialTLS = func(network, addr string) (net.Conn, error) {
		return dialUTLS(network, addr, customSpec)
	}
	
	return &http.Client{
		Transport: utlsTransport,
		Timeout:   timeout,
	}, nil
}

// parseClientHelloToSpec converts raw ClientHello bytes to uTLS ClientHelloSpec
func parseClientHelloToSpec(clientHelloBytes []byte) (*utls.ClientHelloSpec, error) {
	// This is a simplified implementation
	// In a real scenario, you would need to properly parse the ClientHello message
	// and extract cipher suites, extensions, etc.
	
	if len(clientHelloBytes) < 43 { // Minimum ClientHello size
		return nil, fmt.Errorf("ClientHello data too short: %d bytes", len(clientHelloBytes))
	}
	
	// Create a basic custom spec based on the hex data
	// This is a placeholder implementation - you would need to implement
	// proper ClientHello parsing based on RFC 5246/8446
	customSpec := &utls.ClientHelloSpec{
		TLSVersMin: utls.VersionTLS12,
		TLSVersMax: utls.VersionTLS13,
		CipherSuites: []uint16{
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		CompressionMethods: []uint8{0}, // No compression
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.X25519,
				utls.CurveP256,
				utls.CurveP384,
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []uint8{0}},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.PSSWithSHA256,
				utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.PSSWithSHA384,
				utls.PKCS1WithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA512,
			}},
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
		},
	}
	
	return customSpec, nil
}

// dialUTLS establishes a uTLS connection with custom fingerprint
func dialUTLS(network, addr string, spec *utls.ClientHelloSpec) (net.Conn, error) {
	dialConn, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	
	uTLSConn := utls.UClient(dialConn, &utls.Config{
		ServerName:         getHostFromAddr(addr),
		InsecureSkipVerify: true,
	}, utls.HelloCustom)
	
	if err := uTLSConn.ApplyPreset(spec); err != nil {
		dialConn.Close()
		return nil, err
	}
	
	if err := uTLSConn.Handshake(); err != nil {
		dialConn.Close()
		return nil, err
	}
	
	return uTLSConn, nil
}

// getHostFromAddr extracts hostname from address string
func getHostFromAddr(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}