package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"nora/internal/analyzer"
)

func JSON(w io.Writer, res analyzer.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(res)
}

func Text(w io.Writer, res analyzer.Result) error {
	writeSection(w, "Summary")
	fmt.Fprintf(w, "Total requests: %d\n", res.TotalRequests)
	fmt.Fprintf(w, "Unique client IPs: %d\n", res.UniqueClientIPs)
	fmt.Fprintf(w, "Total response bytes: %d\n", res.TotalResponseBytes)
	fmt.Fprintf(w, "Average response size: %.2f\n", res.AverageResponseSize)
	if res.EarliestTimestamp != nil {
		fmt.Fprintf(w, "Earliest timestamp: %s\n", res.EarliestTimestamp.Format(time.RFC3339))
	}
	if res.LatestTimestamp != nil {
		fmt.Fprintf(w, "Latest timestamp: %s\n", res.LatestTimestamp.Format(time.RFC3339))
	}

	writeSection(w, "Status Codes")
	writeMap(w, res.StatusCodes)
	writeSection(w, "HTTP Methods")
	writeMap(w, res.Methods)
	writeSection(w, "Top Paths")
	writeItems(w, res.TopPaths)
	writeSection(w, "Top Clients")
	writeItems(w, res.TopClients)
	writeSection(w, "Top Referrers")
	writeItems(w, res.TopReferrers)
	writeSection(w, "Top User Agents")
	writeItems(w, res.TopUserAgents)
	writeSection(w, "Traffic by Hour")
	for _, item := range res.TrafficByHour {
		fmt.Fprintf(w, "%s  %d\n", item.Hour.Format("2006-01-02 15:00"), item.Count)
	}
	writeSection(w, "Parser Statistics")
	fmt.Fprintf(w, "Parsed lines: %d\n", res.ParsedLines)
	fmt.Fprintf(w, "Malformed lines: %d\n", res.MalformedLines)
	return nil
}

func writeSection(w io.Writer, name string) {
	fmt.Fprintf(w, "\n%s\n%s\n", name, strings.Repeat("-", len(name)))
}

func writeMap(w io.Writer, values map[string]int64) {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Fprintf(w, "%s  %d\n", key, values[key])
	}
}

func writeItems(w io.Writer, items []analyzer.Item) {
	for _, item := range items {
		fmt.Fprintf(w, "%s  %d\n", item.Value, item.Count)
	}
}
