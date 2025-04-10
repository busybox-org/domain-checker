// HTTP resolver
// Detect IP address by HTTP / HTTPS response

package http

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/busybox-org/cert-checker/internal/resolvers/base"
)

type HTTPDetector struct {
	URL string `json:"url"`
}

func scoreOfTLS(t *tls.ConnectionState) float64 {
	if t == nil { // HTTP
		return 0.1
	}
	switch t.Version {
	case tls.VersionTLS13:
		return 1.0
	case tls.VersionTLS12:
		return 0.8
	case tls.VersionTLS11:
		return 0.6
	case tls.VersionTLS10:
		return 0.4
	default:
		return 0.2
	}
}

func (p HTTPDetector) RetrieveIP() (*base.ScoredIP, error) {
	client := http.Client{}
	resp, err := client.Get(p.URL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	ipStr := strings.TrimSpace(string(body))
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, &base.NotRetrievedError{}
	}
	return &base.ScoredIP{IP: ip, Score: scoreOfTLS(resp.TLS)}, nil
}

func (p HTTPDetector) String() string {
	return p.URL
}

func (p HTTPDetector) Type() string {
	return "HTTP"
}
