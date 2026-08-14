package analyzer

import (
	"sort"
	"strconv"
	"time"

	"nora/internal/parser"
	"nora/internal/privacy"
)

type Options struct {
	Top         int
	Since       *time.Time
	Until       *time.Time
	AnonymizeIP bool
}

type Result struct {
	TotalRequests       int64            `json:"total_requests"`
	ParsedLines         int64            `json:"parsed_lines"`
	MalformedLines      int64            `json:"malformed_lines"`
	UniqueClientIPs     int              `json:"unique_client_ips"`
	TotalResponseBytes  int64            `json:"total_response_bytes"`
	AverageResponseSize float64          `json:"average_response_size"`
	Methods             map[string]int64 `json:"methods"`
	StatusCodes         map[string]int64 `json:"status_codes"`
	StatusFamilies      map[string]int64 `json:"status_families"`
	TopPaths            []Item           `json:"top_paths"`
	TopClients          []Item           `json:"top_clients"`
	TopReferrers        []Item           `json:"top_referrers"`
	TopUserAgents       []Item           `json:"top_user_agents"`
	TrafficByHour       []HourItem       `json:"traffic_by_hour"`
	EarliestTimestamp   *time.Time       `json:"earliest_timestamp,omitempty"`
	LatestTimestamp     *time.Time       `json:"latest_timestamp,omitempty"`
}

type Item struct {
	Value string `json:"value"`
	Count int64  `json:"count"`
}

type HourItem struct {
	Hour  time.Time `json:"hour"`
	Count int64     `json:"count"`
}

type Analyzer struct {
	opts         Options
	result       Result
	clients      map[string]struct{}
	clientCounts map[string]int64
	paths        map[string]int64
	referrers    map[string]int64
	agents       map[string]int64
	hours        map[time.Time]int64
}

func New(opts Options) *Analyzer {
	if opts.Top <= 0 {
		opts.Top = 10
	}
	return &Analyzer{
		opts: opts,
		result: Result{
			Methods:        map[string]int64{},
			StatusCodes:    map[string]int64{},
			StatusFamilies: map[string]int64{"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0},
		},
		clients:      map[string]struct{}{},
		clientCounts: map[string]int64{},
		paths:        map[string]int64{},
		referrers:    map[string]int64{},
		agents:       map[string]int64{},
		hours:        map[time.Time]int64{},
	}
}

func (a *Analyzer) AddMalformed() {
	a.result.MalformedLines++
}

func (a *Analyzer) Add(rec parser.Record) {
	if a.opts.Since != nil && rec.Time.Before(*a.opts.Since) {
		return
	}
	if a.opts.Until != nil && rec.Time.After(*a.opts.Until) {
		return
	}

	client := rec.Client
	if a.opts.AnonymizeIP {
		client = privacy.AnonymizeIP(client)
	}
	path := privacy.PathOnly(rec.Target)

	a.result.ParsedLines++
	a.result.TotalRequests++
	a.result.TotalResponseBytes += rec.Bytes
	a.result.Methods[rec.Method]++
	a.result.StatusCodes[statusKey(rec.Status)]++
	a.result.StatusFamilies[familyKey(rec.Status)]++
	a.clients[client] = struct{}{}
	a.clientCounts[client]++
	a.paths[path]++
	a.referrers[emptyDash(rec.Referrer)]++
	a.agents[emptyDash(rec.UserAgent)]++
	a.hours[rec.Time.Truncate(time.Hour)]++

	if a.result.EarliestTimestamp == nil || rec.Time.Before(*a.result.EarliestTimestamp) {
		t := rec.Time
		a.result.EarliestTimestamp = &t
	}
	if a.result.LatestTimestamp == nil || rec.Time.After(*a.result.LatestTimestamp) {
		t := rec.Time
		a.result.LatestTimestamp = &t
	}
}

func (a *Analyzer) Result() Result {
	res := a.result
	res.UniqueClientIPs = len(a.clients)
	if res.TotalRequests > 0 {
		res.AverageResponseSize = float64(res.TotalResponseBytes) / float64(res.TotalRequests)
	}
	res.TopPaths = topN(a.paths, a.opts.Top)
	res.TopClients = topN(a.clientCounts, a.opts.Top)
	res.TopReferrers = topN(a.referrers, a.opts.Top)
	res.TopUserAgents = topN(a.agents, a.opts.Top)
	res.TrafficByHour = sortedHours(a.hours)
	return res
}

func statusKey(status int) string {
	return strconv.Itoa(status)
}

func familyKey(status int) string {
	if status >= 200 && status <= 599 {
		return strconv.Itoa(status/100) + "xx"
	}
	return "other"
}

func emptyDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func topN(counts map[string]int64, n int) []Item {
	items := make([]Item, 0, len(counts))
	for value, count := range counts {
		items = append(items, Item{Value: privacy.SanitizeText(value), Count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count == items[j].Count {
			return items[i].Value < items[j].Value
		}
		return items[i].Count > items[j].Count
	})
	if len(items) > n {
		return items[:n]
	}
	return items
}

func sortedHours(counts map[time.Time]int64) []HourItem {
	items := make([]HourItem, 0, len(counts))
	for hour, count := range counts {
		items = append(items, HourItem{Hour: hour, Count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].Hour.Before(items[j].Hour)
	})
	return items
}
