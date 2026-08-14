package parser

import "testing"

func TestParseCommonFormat(t *testing.T) {
	rec, err := Parse(`127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326`)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Client != "127.0.0.1" || rec.Method != "GET" || rec.Target != "/index.html" || rec.Status != 200 || rec.Bytes != 2326 {
		t.Fatalf("unexpected record: %+v", rec)
	}
}

func TestParseCombinedFormat(t *testing.T) {
	rec, err := Parse(`2001:db8::1 - - [10/Oct/2000:13:56:36 -0700] "POST /submit?q=1 HTTP/1.1" 404 - "https://example.com/" "Mozilla/5.0"`)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Client != "2001:db8::1" || rec.Referrer != "https://example.com/" || rec.UserAgent != "Mozilla/5.0" || rec.Bytes != 0 {
		t.Fatalf("unexpected record: %+v", rec)
	}
}

func TestParseEscapedQuotes(t *testing.T) {
	rec, err := Parse(`127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.1" 200 10 "-" "agent \"quoted\""`)
	if err != nil {
		t.Fatal(err)
	}
	if rec.UserAgent != `agent "quoted"` {
		t.Fatalf("unexpected user agent: %q", rec.UserAgent)
	}
}

func TestParseMalformed(t *testing.T) {
	if _, err := Parse(`not a valid line`); err == nil {
		t.Fatal("expected malformed error")
	}
}
