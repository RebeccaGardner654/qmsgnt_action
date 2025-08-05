package main

import (
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	utls "github.com/refraction-networking/utls"
)

// 抓包的十六进制ClientHello数据
const rawClientHello = "02000000450007a0c7fb4000800600007f0000017f0000014ba22328e840b219aad63331501800ff243c000016030107730100076f0303f7d3af50ec2f67b9023eff394d0fac08c4c287e28a0f95329b126eae152e6f1f208dbd2ca629eaea9875e6fdbd1c0d17b4c86b8bf64815e988e92160806959a0ec00200a0a130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010007064a4a0000fe0d00ba0000010001ab0020537ef396d022dcab121a8e33e8a74a7f85816f4c2a773f379b2a4c39ba62332a009076f71dd87b55342dfec1b3b189267ecc3bbb5b3f9a3d0d492234e5220900ac33ad87d60ea0b58609cb5044caf237ed1b2e02ec5698036c7045b5ee302d8e2606574b1aeb016b6a57de7cd70838b46f0af9925bb5412a6149d11b01eb880d090c677c5a5d1826fef0a983060ca33d3d6643e532d8285eac202be5e28915eddec1ac97ac30652fa0a34cc77090bcc92a3f000b00020100446900050003026832003304ef04ed8a8a000100639904c03a559e33ed7ac6f4694b85150f88b0eaf79f8b42e1afb5460c684e9a8699952ace18313c702c867b40d2964d79acb428ab7e923c145b9471622aad51894263bac9e0f966991024f2330a59cac6952970f3d5399603ab8f884add735f16617e988c6a9c71a56e0c127e92111a56c86c73536108290f504f37279630ec511a9720242a78dea21b2170700649578225539c3b708d7b22137034755c9ec8b7b602f0ac74d8c7a05736f3822ac3777ac1e61fdd46086b3a95cd5897c98396a9772f6facbb0f29733db3cf8b495d17d2bed612379ff1625279648f540bb8cb661d266a5948bb3423834b489e0b75624970bb8619884a31b63c543f42806a4b509805982b6eb0befd079513a19339a20a863b96aca2cbd3c72eeef56449d51c9a587d611149aea88ef5c0994ae5332cbca9b061b4d24236d348544ae9cd656c80c30b7b1b652a685a928ebaa112137d6352606f762fb302cb9fe86e8693ad7d8a7befba2473bb4a4d1101230317b35887dfe1c49dd6b4fe8a1824f137c9ab30b6a7a822810b21fa5ebb5c80a9e5139211053278195a518d00fca70d757053725a92f6c999dc8422c9253165767f45809d560a21e501436001f4c2a9abe4495e803b67949cf371b9ba562c446a1d48530dcef25831c64b7a36bd60824eae30b96678bcf58443bb033313659b494325668c6b5dc3ae6cc032399cbd27b70bcf44b3da5b052e2326f00c2acb345a22f072d542bd8cf91309017057f59cf3e4ac3cfc50ed17446f394025c064a47128ec6a3d878c13af9b40fcfbc8f5899efd202ff8758cf9948777ba7778a702eaa78617bc0a0ad97c3bd9b6f70122f982b77c502127680198f21e2847bc1f367d2e5315d79c304a580c46ec52685340582b7d492352341c45414b0be8a4637fc2962691c68a178041d490b0e01a42a80c94833b8b07792a7415253824700448c0e5b92fcc5d1748c663024742c73fb9d07a5fa22a831b5f578226c1fb269b4b56c3ab64edbc8c613a5d55078ec43a27f387192cfc0180f7adcf4a1e3e70204bb4536a51b2c057478fe751a99a701794b377c355d564c99b75add547b0103241d586c742f93704850ec47b4444bb66bafc187d602d80e085536770f6e9bb298b537c53c9e76a64c74c0d31b429c26c01de2089def59f22f33362483ca1f28c61a764e30598f1e6022a933187bb954e588e015a7d42d69286cac58d2048a58a90369bcc2f717e9f503fc5334dfa140f9fa7391a8a5e8653353e5c9b4cf71f9872af86d697a2333e0de638737518eae3015b8a2a0d96a02f3cca2fb19cdd9955b9378fb583aa64020cc7a8c9446085f8852ac3e2251b000d2fd3c3d9eb6d515124e1e1857293674af7cb07a52cf728cf8b77b4c13c5913510d0bac2baaf5134afbaa1c820cc7008242b26f55ba7965b12eb592acc2322dc4d54ea6e0588db6a0237681981182c5ca23f8573f9c5187140008bb916aa6ab2f94a1be4326a168ea4c76da3786119117f3512f5557b8229ec9d8abc5dace09f02c38593be8b05c5c30491ee0616cb682dd720acd73ce91769de2876ab3415f2c910e666078788787553367c1e90eaa98494595b766809d6d0a74b6f97262503ad0313cc97cc9baec455834aebef7891547b7f6428a0ceac3c59299a28b6a6b7c5936d11bf834a3b19f56abea5a6a25d5ac95e6b5cd405b63980d4cf363acffa4e1001d0020adc6e15363007fbd8d1518f4dcd71442e418a63b8fee647f5bde08d8959b9a0f000d00120010040308040401050308050501080606010000001f001d00001a6d642d68352d676174657761792e73687578696e79632e636f6dff01000100002d00020101001b0003020002000500050100000000002300b0276e2549a1fe2b60252c23bd0e3fe914d48e2736de1073a4e35a6397efdc5be999eec3d4c7218ee7583f5cd364edb52d0c10c52751b3a93c0cfb3e181f78ae255a07f4f4f9f756cf9cae1ec53d88e97aed42cfe3ef7dadfbba0edde722b3a6e75ccc6c028323d46129d4e181f29555339505f46dcddb8eeed071d5f09f098fc0f1501b78b58c54133eda4d9b1b2f476fcca6e8fffbb61db50b345141d7406b12df4e015efe2a77b22777ad9498066267002b0007063a3a030403030010000e000c02683208687474702f312e3100120000000a000c000a8a8a6399001d00170018001700007a7a000100"

// createCustomTLSClient 使用抓包数据创建自定义TLS客户端
func createCustomTLSClient() (*http.Client, error) {
	// 解码十六进制数据
	clientHelloBytes, err := hex.DecodeString(rawClientHello)
	if err != nil {
		return nil, fmt.Errorf("failed to decode raw ClientHello: %w", err)
	}

	log.Printf("Decoded ClientHello bytes length: %d", len(clientHelloBytes))

	// 跳过前44字节，从TLS握手记录开始
	if len(clientHelloBytes) < 44 {
		return nil, fmt.Errorf("ClientHello data too short")
	}
	tlsData := clientHelloBytes[44:]

	// 创建Fingerprinter并解析ClientHello
	fingerprinter := &utls.Fingerprinter{}
	clientHelloSpec, err := fingerprinter.FingerprintClientHello(tlsData)
	if err != nil {
		return nil, fmt.Errorf("failed to fingerprint ClientHello: %w", err)
	}

	log.Printf("Successfully fingerprinted ClientHello with %d cipher suites", len(clientHelloSpec.CipherSuites))

	// 创建自定义TLS配置
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // 测试环境下跳过证书验证
	}

	// 创建HTTP传输
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		DialTLS: func(network, addr string) (net.Conn, error) {
			conn, err := net.Dial(network, addr)
			if err != nil {
				return nil, err
			}

			// 使用utls创建TLS连接
			uconn := utls.UClient(conn, &utls.Config{
				InsecureSkipVerify: true,
			}, utls.HelloCustom)

			// 应用自定义指纹
			if err := uconn.ApplyPreset(clientHelloSpec); err != nil {
				conn.Close()
				return nil, fmt.Errorf("failed to apply custom fingerprint: %w", err)
			}

			// 执行TLS握手
			if err := uconn.Handshake(); err != nil {
				conn.Close()
				return nil, fmt.Errorf("TLS handshake failed: %w", err)
			}

			log.Printf("TLS handshake completed successfully with custom fingerprint")
			return uconn, nil
		},
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}, nil
}

// createFallbackClient 创建标准HTTP客户端作为回退
func createFallbackClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
	}
}

// makeRequest 执行HTTP请求，优先使用自定义TLS，失败时回退到标准HTTP
func makeRequest(url string) error {
	log.Printf("Attempting to make request to: %s", url)

	// 首先尝试使用自定义TLS指纹
	customClient, err := createCustomTLSClient()
	if err != nil {
		log.Printf("Failed to create custom TLS client: %v, falling back to standard HTTP", err)
		return makeRequestWithFallback(url)
	}

	resp, err := customClient.Get(url)
	if err != nil {
		log.Printf("Custom TLS request failed: %v, falling back to standard HTTP", err)
		return makeRequestWithFallback(url)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	log.Printf("Custom TLS request successful! Status: %s, Body length: %d", resp.Status, len(body))
	return nil
}

// makeRequestWithFallback 使用标准HTTP客户端作为回退
func makeRequestWithFallback(url string) error {
	log.Printf("Using fallback standard HTTP client")
	
	fallbackClient := createFallbackClient()
	
	resp, err := fallbackClient.Get(url)
	if err != nil {
		return fmt.Errorf("fallback HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read fallback response body: %w", err)
	}

	log.Printf("Fallback HTTP request successful! Status: %s, Body length: %d", resp.Status, len(body))
	return nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("Starting TLS fingerprint application...")

	// 测试URL - 使用一个简单的测试或使用httpbin的IP地址
	testURL := "https://www.google.com" // 尝试一个更可靠的测试URL

	if err := makeRequest(testURL); err != nil {
		log.Printf("Request failed: %v", err)
		// 不要fatalf，让程序正常结束以便查看日志
	}

	log.Println("Application completed")
}