package tui

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"nora/internal/analyzer"
	"nora/internal/config"
	"nora/internal/report"
)

type AnalyzeFunc func(target config.RemoteTarget, opts analyzer.Options) (analyzer.Result, error)

type App struct {
	in      *bufio.Reader
	out     io.Writer
	cfg     config.File
	analyze AnalyzeFunc
}

func New(in io.Reader, out io.Writer, cfg config.File, analyze AnalyzeFunc) *App {
	return &App{
		in:      bufio.NewReader(in),
		out:     out,
		cfg:     cfg,
		analyze: analyze,
	}
}

func (a *App) Run() error {
	for {
		targetName, target, ok, err := a.chooseTarget()
		if err != nil || !ok {
			return err
		}
		opts, ok, err := a.chooseFilters()
		if err != nil || !ok {
			return err
		}
		fmt.Fprintf(a.out, "\nAnalyzing %s (%s)...\n", targetName, target.Path)
		res, err := a.analyze(target, opts)
		if err != nil {
			fmt.Fprintf(a.out, "Error: %v\n", err)
			continue
		}
		if err := a.drillDown(targetName, res); err != nil {
			return err
		}
	}
}

func (a *App) chooseTarget() (string, config.RemoteTarget, bool, error) {
	names := make([]string, 0, len(a.cfg.RemoteTargets))
	for name := range a.cfg.RemoteTargets {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return "", config.RemoteTarget{}, false, fmt.Errorf("no remote targets configured")
	}

	fmt.Fprintln(a.out, "\nnora Remote Targets")
	for i, name := range names {
		target := a.cfg.RemoteTargets[name]
		sudo := ""
		if target.Sudo {
			sudo = " sudo"
		}
		fmt.Fprintf(a.out, "%d. %s  %s:%s%s\n", i+1, name, target.Host, target.Path, sudo)
	}
	fmt.Fprintln(a.out, "q. quit")
	choice, err := a.prompt("Target")
	if err != nil || strings.EqualFold(choice, "q") {
		return "", config.RemoteTarget{}, false, err
	}
	idx, err := strconv.Atoi(choice)
	if err != nil || idx < 1 || idx > len(names) {
		fmt.Fprintln(a.out, "Invalid target.")
		return a.chooseTarget()
	}
	name := names[idx-1]
	return name, a.cfg.RemoteTargets[name], true, nil
}

func (a *App) chooseFilters() (analyzer.Options, bool, error) {
	opts := analyzer.Options{Top: 10}
	top, err := a.promptDefault("Top count", "10")
	if err != nil {
		return opts, false, err
	}
	if top != "" {
		n, err := strconv.Atoi(top)
		if err != nil || n <= 0 {
			fmt.Fprintln(a.out, "Invalid top count, using 10.")
		} else {
			opts.Top = n
		}
	}
	since, err := a.promptDefault("Since (RFC3339 or NGINX timestamp, blank for all)", "")
	if err != nil {
		return opts, false, err
	}
	if since != "" {
		t, err := parseTime(since)
		if err != nil {
			fmt.Fprintf(a.out, "Invalid since timestamp: %v\n", err)
			return a.chooseFilters()
		}
		opts.Since = t
	}
	until, err := a.promptDefault("Until (RFC3339 or NGINX timestamp, blank for all)", "")
	if err != nil {
		return opts, false, err
	}
	if until != "" {
		t, err := parseTime(until)
		if err != nil {
			fmt.Fprintf(a.out, "Invalid until timestamp: %v\n", err)
			return a.chooseFilters()
		}
		opts.Until = t
	}
	anonymize, err := a.promptDefault("Anonymize IPs (y/N)", "n")
	if err != nil {
		return opts, false, err
	}
	opts.AnonymizeIP = strings.EqualFold(anonymize, "y") || strings.EqualFold(anonymize, "yes")
	return opts, true, nil
}

func (a *App) drillDown(targetName string, res analyzer.Result) error {
	for {
		fmt.Fprintf(a.out, "\nnora Report: %s\n", targetName)
		fmt.Fprintln(a.out, "1. Summary")
		fmt.Fprintln(a.out, "2. Status codes")
		fmt.Fprintln(a.out, "3. HTTP methods")
		fmt.Fprintln(a.out, "4. Top paths")
		fmt.Fprintln(a.out, "5. Top clients")
		fmt.Fprintln(a.out, "6. Top referrers")
		fmt.Fprintln(a.out, "7. Top user agents")
		fmt.Fprintln(a.out, "8. Traffic by hour")
		fmt.Fprintln(a.out, "9. Full text report")
		fmt.Fprintln(a.out, "10. Save JSON report")
		fmt.Fprintln(a.out, "b. back to targets")
		fmt.Fprintln(a.out, "q. quit")
		choice, err := a.prompt("View")
		if err != nil {
			return err
		}
		switch strings.ToLower(choice) {
		case "1":
			a.showSummary(res)
		case "2":
			showMap(a.out, res.StatusCodes)
		case "3":
			showMap(a.out, res.Methods)
		case "4":
			showItems(a.out, res.TopPaths)
		case "5":
			showItems(a.out, res.TopClients)
		case "6":
			showItems(a.out, res.TopReferrers)
		case "7":
			showItems(a.out, res.TopUserAgents)
		case "8":
			showHours(a.out, res.TrafficByHour)
		case "9":
			if err := report.Text(a.out, res); err != nil {
				return err
			}
		case "10":
			if err := a.saveJSON(targetName, res); err != nil {
				fmt.Fprintf(a.out, "Save failed: %v\n", err)
			}
		case "b":
			return nil
		case "q":
			os.Exit(0)
		default:
			fmt.Fprintln(a.out, "Invalid view.")
		}
	}
}

func (a *App) showSummary(res analyzer.Result) {
	fmt.Fprintf(a.out, "\nTotal requests: %d\n", res.TotalRequests)
	fmt.Fprintf(a.out, "Parsed lines: %d\n", res.ParsedLines)
	fmt.Fprintf(a.out, "Malformed lines: %d\n", res.MalformedLines)
	fmt.Fprintf(a.out, "Unique client IPs: %d\n", res.UniqueClientIPs)
	fmt.Fprintf(a.out, "Total response bytes: %d\n", res.TotalResponseBytes)
	fmt.Fprintf(a.out, "Average response size: %.2f\n", res.AverageResponseSize)
	if res.EarliestTimestamp != nil {
		fmt.Fprintf(a.out, "Earliest: %s\n", res.EarliestTimestamp.Format(time.RFC3339))
	}
	if res.LatestTimestamp != nil {
		fmt.Fprintf(a.out, "Latest: %s\n", res.LatestTimestamp.Format(time.RFC3339))
	}
}

func (a *App) saveJSON(targetName string, res analyzer.Result) error {
	path, err := a.promptDefault("Output path", fmt.Sprintf("%s-report.json", targetName))
	if err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := report.JSON(f, res); err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Saved %s\n", path)
	return nil
}

func (a *App) prompt(label string) (string, error) {
	fmt.Fprintf(a.out, "%s: ", label)
	line, err := a.in.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func (a *App) promptDefault(label, fallback string) (string, error) {
	if fallback == "" {
		return a.prompt(label)
	}
	fmt.Fprintf(a.out, "%s [%s]: ", label, fallback)
	line, err := a.in.ReadString('\n')
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(line)
	if value == "" {
		return fallback, nil
	}
	return value, nil
}

func parseTime(value string) (*time.Time, error) {
	layouts := []string{time.RFC3339, "02/Jan/2006:15:04:05 -0700"}
	var last error
	for _, layout := range layouts {
		t, err := time.Parse(layout, value)
		if err == nil {
			return &t, nil
		}
		last = err
	}
	return nil, last
}

func showMap(w io.Writer, values map[string]int64) {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Fprintf(w, "%s  %d\n", key, values[key])
	}
}

func showItems(w io.Writer, items []analyzer.Item) {
	for _, item := range items {
		fmt.Fprintf(w, "%s  %d\n", item.Value, item.Count)
	}
}

func showHours(w io.Writer, items []analyzer.HourItem) {
	for _, item := range items {
		fmt.Fprintf(w, "%s  %d\n", item.Hour.Format("2006-01-02 15:00"), item.Count)
	}
}
