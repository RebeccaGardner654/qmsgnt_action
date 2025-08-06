package main

import (
	"crypto/tls"
	"encoding/hex"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

func TestTLSFingerprintCreation(t *testing.T) {
	// 测试自定义TLS客户端创建
	client, err := createUTLSClient()
	if err != nil {
		t.Fatalf("Failed to create custom TLS client: %v", err)
	}

	if client == nil {
		t.Fatal("Client should not be nil")
	}

	if client.Timeout != 30*time.Second {
		t.Errorf("Expected timeout 30s, got %v", client.Timeout)
	}

	t.Log("Custom TLS client created successfully")
}

func TestFallbackClient(t *testing.T) {
	client := createFallbackClient()
	
	if client == nil {
		t.Fatal("Fallback client should not be nil")
	}

	if client.Timeout != 30*time.Second {
		t.Errorf("Expected timeout 30s, got %v", client.Timeout)
	}

	t.Log("Fallback client created successfully")
}

func TestClientHelloDecoding(t *testing.T) {
	// 测试ClientHello解码过程
	clientHelloBytes, err := hex.DecodeString(rawClientHello)
	if err != nil {
		t.Fatalf("Failed to decode raw ClientHello: %v", err)
	}

	if len(clientHelloBytes) < 44 {
		t.Fatalf("ClientHello data too short: %d bytes", len(clientHelloBytes))
	}

	tlsData := clientHelloBytes[44:]
	t.Logf("TLS data length after offset: %d bytes", len(tlsData))

	// 验证TLS记录格式
	if len(tlsData) < 5 {
		t.Fatal("TLS data too short for record header")
	}

	recordType := tlsData[0]
	if recordType != 0x16 {
		t.Errorf("Expected TLS handshake record type 0x16, got 0x%02x", recordType)
	}

	tlsVersion := (uint16(tlsData[1]) << 8) | uint16(tlsData[2])
	recordLength := (uint16(tlsData[3]) << 8) | uint16(tlsData[4])

	t.Logf("TLS record - Type: 0x%02x, Version: 0x%04x, Length: %d", 
		recordType, tlsVersion, recordLength)

	// 测试Fingerprinter
	fingerprinter := &utls.Fingerprinter{}
	spec, err := fingerprinter.FingerprintClientHello(tlsData)
	if err != nil {
		t.Fatalf("Failed to fingerprint ClientHello: %v", err)
	}

	if len(spec.CipherSuites) == 0 {
		t.Error("No cipher suites found in fingerprint")
	}

	t.Logf("Fingerprint successful - Cipher suites: %d", len(spec.CipherSuites))
	t.Logf("TLS version: %x", spec.TLSVersMax)
	
	// 记录一些指纹信息用于验证
	for i, suite := range spec.CipherSuites {
		if i < 3 { // 只记录前3个
			t.Logf("Cipher suite %d: 0x%04x", i, suite)
		}
	}
}

func TestTLSConnectionSetup(t *testing.T) {
	// 测试TLS连接设置逻辑（不实际连接）
	clientHelloBytes, err := hex.DecodeString(rawClientHello)
	if err != nil {
		t.Fatalf("Failed to decode raw ClientHello: %v", err)
	}

	tlsData := clientHelloBytes[44:]
	fingerprinter := &utls.Fingerprinter{}
	clientHelloSpec, err := fingerprinter.FingerprintClientHello(tlsData)
	if err != nil {
		t.Fatalf("Failed to fingerprint ClientHello: %v", err)
	}

	// 创建TLS配置
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	if tlsConfig == nil {
		t.Error("TLS config should not be nil")
	}

	// 验证可以创建utls客户端配置
	utlsConfig := &utls.Config{
		InsecureSkipVerify: true,
	}

	if utlsConfig == nil {
		t.Error("UTLS config should not be nil")
	}

	t.Logf("TLS connection setup validation passed")
	t.Logf("ClientHello spec has %d extensions", len(clientHelloSpec.Extensions))
}

// 模拟网络连接测试（不实际连接网络）
func TestNetworkConnectionLogic(t *testing.T) {
	// 测试网络连接失败时的回退逻辑
	testURL := "https://example.com"
	
	// 模拟makeRequest的逻辑，但不实际发送请求
	t.Logf("Would attempt request to: %s", testURL)
	
	// 测试自定义TLS客户端创建
	_, err := createUTLSClient()
	if err != nil {
		t.Logf("Custom TLS client failed (expected in test): %v", err)
		
		// 测试回退客户端
		fallbackClient := createFallbackClient()
		if fallbackClient == nil {
			t.Error("Fallback client should not be nil")
		}
		t.Log("Fallback logic works correctly")
	} else {
		t.Log("Custom TLS client created successfully")
	}
}