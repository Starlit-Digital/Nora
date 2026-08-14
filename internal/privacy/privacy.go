package privacy

import (
	"net"
	"net/url"
	"strings"
)

func PathOnly(target string) string {
	if target == "" || target == "-" {
		return target
	}
	if u, err := url.ParseRequestURI(target); err == nil && u.Path != "" {
		return u.Path
	}
	if i := strings.IndexByte(target, '?'); i >= 0 {
		return target[:i]
	}
	return target
}

func AnonymizeIP(value string) string {
	ip := net.ParseIP(value)
	if ip == nil {
		return value
	}
	if v4 := ip.To4(); v4 != nil {
		return net.IPv4(v4[0], v4[1], v4[2], 0).String()
	}
	v6 := ip.To16()
	if v6 == nil {
		return value
	}
	masked := make(net.IP, len(v6))
	copy(masked, v6)
	for i := 6; i < len(masked); i++ {
		masked[i] = 0
	}
	return masked.String()
}

func SanitizeText(value string) string {
	var b strings.Builder
	for _, r := range value {
		if r == '\t' || r == '\n' || r == '\r' {
			b.WriteByte(' ')
			continue
		}
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
