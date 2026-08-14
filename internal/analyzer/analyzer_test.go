package analyzer

import (
	"testing"
	"time"

	"nora/internal/parser"
)

func TestAnalyzerAggregatesAndOrdersTopN(t *testing.T) {
	base := time.Date(2000, 10, 10, 13, 55, 0, 0, time.UTC)
	a := New(Options{Top: 2})
	a.Add(parser.Record{Client: "10.0.0.1", Time: base, Method: "GET", Target: "/b?q=1", Status: 200, Bytes: 100, Referrer: "-", UserAgent: "curl"})
	a.Add(parser.Record{Client: "10.0.0.2", Time: base.Add(time.Minute), Method: "GET", Target: "/a", Status: 404, Bytes: 300, Referrer: "-", UserAgent: "curl"})
	a.Add(parser.Record{Client: "10.0.0.2", Time: base.Add(time.Hour), Method: "POST", Target: "/a?secret=1", Status: 500, Bytes: 500, Referrer: "https://example.com", UserAgent: "browser"})
	a.AddMalformed()

	res := a.Result()
	if res.TotalRequests != 3 || res.MalformedLines != 1 || res.UniqueClientIPs != 2 {
		t.Fatalf("unexpected summary: %+v", res)
	}
	if res.StatusFamilies["2xx"] != 1 || res.StatusFamilies["4xx"] != 1 || res.StatusFamilies["5xx"] != 1 {
		t.Fatalf("unexpected status families: %+v", res.StatusFamilies)
	}
	if res.TopPaths[0].Value != "/a" || res.TopPaths[0].Count != 2 {
		t.Fatalf("unexpected top paths: %+v", res.TopPaths)
	}
	if res.TopClients[0].Value != "10.0.0.2" || res.TopClients[0].Count != 2 {
		t.Fatalf("unexpected top clients: %+v", res.TopClients)
	}
	if len(res.TrafficByHour) != 2 {
		t.Fatalf("unexpected hourly traffic: %+v", res.TrafficByHour)
	}
}

func TestAnalyzerTimeFiltering(t *testing.T) {
	base := time.Date(2000, 10, 10, 13, 0, 0, 0, time.UTC)
	since := base.Add(time.Hour)
	until := base.Add(2 * time.Hour)
	a := New(Options{Since: &since, Until: &until})
	a.Add(parser.Record{Client: "10.0.0.1", Time: base, Method: "GET", Target: "/", Status: 200})
	a.Add(parser.Record{Client: "10.0.0.1", Time: since, Method: "GET", Target: "/", Status: 200})
	a.Add(parser.Record{Client: "10.0.0.1", Time: until.Add(time.Minute), Method: "GET", Target: "/", Status: 200})

	if got := a.Result().TotalRequests; got != 1 {
		t.Fatalf("TotalRequests = %d", got)
	}
}

func TestAnalyzerAnonymizesBeforeAggregation(t *testing.T) {
	now := time.Now()
	a := New(Options{AnonymizeIP: true})
	a.Add(parser.Record{Client: "192.168.1.10", Time: now, Method: "GET", Target: "/", Status: 200})
	a.Add(parser.Record{Client: "192.168.1.20", Time: now, Method: "GET", Target: "/", Status: 200})

	res := a.Result()
	if res.UniqueClientIPs != 1 || res.TopClients[0].Value != "192.168.1.0" || res.TopClients[0].Count != 2 {
		t.Fatalf("unexpected anonymized clients: %+v", res.TopClients)
	}
}
