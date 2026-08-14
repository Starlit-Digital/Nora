package report

import (
	"strings"
	"testing"

	"nora/internal/analyzer"
)

func TestTextReportGeneration(t *testing.T) {
	var b strings.Builder
	err := Text(&b, analyzer.Result{
		TotalRequests: 1,
		ParsedLines:   1,
		StatusCodes:   map[string]int64{"200": 1},
		Methods:       map[string]int64{"GET": 1},
		TopPaths:      []analyzer.Item{{Value: "/", Count: 1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"Summary", "Status Codes", "HTTP Methods", "Top Paths", "Parser Statistics"} {
		if !strings.Contains(out, want) {
			t.Fatalf("report missing %q:\n%s", want, out)
		}
	}
}
