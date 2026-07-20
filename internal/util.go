package internal

import (
	"encoding/binary"
	"net"
	"regexp"
	"strings"
)

var sanitizeRegex = regexp.MustCompile(`[^\x20-\x7E]`)

func Sanitize(s string) string {
	return sanitizeRegex.ReplaceAllString(s, "")
}

func InetPton(ipStr string) []byte {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return []byte{0, 0, 0, 0}
	}
	return ip
}

func InetNtop(b []byte) string {
	if len(b) < 4 {
		return "0.0.0.0"
	}
	return net.IPv4(b[0], b[1], b[2], b[3]).String()
}

func ExtractIPChain(rHeaders map[string][]string, remoteAddr string) []string {
	var chain []string
	
	if xff, ok := rHeaders["X-Forwarded-For"]; ok && len(xff) > 0 {
		for _, entry := range strings.Split(xff[0], ",") {
			cleaned := Sanitize(strings.TrimSpace(entry))
			if net.ParseIP(cleaned) != nil {
				chain = append(chain, cleaned)
			}
		}
	}
	
	host, _, _ := net.SplitHostPort(remoteAddr)
	if host == "" {
		host = remoteAddr
	}
	if host != "" {
		chain = append(chain, host)
	}
	
	return chain
}

func CheckSourceAllowed(remoteAddr string, allowedCIDRs []string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	parsedIP := net.ParseIP(host)
	if parsedIP == nil {
		return false
	}

	for _, cidr := range allowedCIDRs {
		if cidr == "*" || cidr == "0.0.0.0/0" {
			return true
		}
		_, subnet, err := net.ParseCIDR(cidr)
		if err == nil && subnet.Contains(parsedIP) {
			return true
		}
	}
	return false
}

func ReadUint16(b []byte, offset int) uint16 {
	return binary.BigEndian.Uint16(b[offset:])
}

func ReadUint32(b []byte, offset int) uint32 {
	return binary.BigEndian.Uint32(b[offset:])
}
