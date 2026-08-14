package privacy

import "testing"

func TestPathOnlyRemovesQueryString(t *testing.T) {
	if got := PathOnly("/search?q=secret&x=1"); got != "/search" {
		t.Fatalf("PathOnly() = %q", got)
	}
}

func TestAnonymizeIPv4(t *testing.T) {
	if got := AnonymizeIP("192.168.10.42"); got != "192.168.10.0" {
		t.Fatalf("AnonymizeIP() = %q", got)
	}
}

func TestAnonymizeIPv6(t *testing.T) {
	if got := AnonymizeIP("2001:db8:abcd:1234:5678::1"); got != "2001:db8:abcd::" {
		t.Fatalf("AnonymizeIP() = %q", got)
	}
}

func TestSanitizeTextDropsControlCharacters(t *testing.T) {
	if got := SanitizeText("ok\x00bad\nnext"); got != "okbad next" {
		t.Fatalf("SanitizeText() = %q", got)
	}
}
