package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"time"

	"nora/internal/analyzer"
	appconfig "nora/internal/config"
	"nora/internal/parser"
	"nora/internal/report"
	"nora/internal/tui"
)

const version = "0.1.0"

const (
	exitOK           = 0
	exitRuntimeError = 1
	exitInvalidArgs  = 2
	exitOpenError    = 3
	exitUnrecognized = 4
)

type config struct {
	path        string
	format      string
	top         int
	since       *time.Time
	until       *time.Time
	anonymizeIP bool
	quiet       bool
	configPath  string
	targetName  string
	listTargets bool
	ssh         sshConfig
}

type sshConfig struct {
	host     string
	user     string
	port     int
	identity string
	sudo     bool
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, os.Stdin))
}

func run(args []string, stdout, stderr io.Writer, stdin io.Reader) int {
	if len(args) > 0 && args[0] == "tui" {
		return runTUI(args[1:], stdout, stderr, stdin)
	}
	cfg, code, err := parseArgs(args, stdout, stderr)
	if err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stderr, err)
		}
		return code
	}

	input, closeFn, code, err := openInput(cfg.path, stdin, cfg.ssh)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return code
	}
	defer closeFn()

	result, code, err := analyze(input, cfg)
	if err != nil {
		if !cfg.quiet {
			fmt.Fprintln(stderr, err)
		}
		return code
	}
	if cfg.quiet {
		return exitOK
	}
	if cfg.format == "json" {
		if err := report.JSON(stdout, result); err != nil {
			fmt.Fprintln(stderr, err)
			return exitRuntimeError
		}
		return exitOK
	}
	if err := report.Text(stdout, result); err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntimeError
	}
	return exitOK
}

func runTUI(args []string, stdout, stderr io.Writer, stdin io.Reader) int {
	fs := flag.NewFlagSet("nora tui", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "nora.config.json", "config file path")
	if err := fs.Parse(args); err != nil {
		return exitInvalidArgs
	}
	cfg, err := appconfig.Load(*configPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitInvalidArgs
	}
	app := tui.New(stdin, stdout, cfg, func(target appconfig.RemoteTarget, opts analyzer.Options) (analyzer.Result, error) {
		sshCfg := sshConfig{
			host:     target.Host,
			user:     target.User,
			port:     target.Port,
			identity: target.Identity,
			sudo:     target.Sudo,
		}
		input, closeFn, _, err := openInput(target.Path, stdin, sshCfg)
		if err != nil {
			return analyzer.Result{}, err
		}
		defer closeFn()
		res, _, err := analyze(input, config{
			path:        target.Path,
			ssh:         sshCfg,
			top:         opts.Top,
			since:       opts.Since,
			until:       opts.Until,
			anonymizeIP: opts.AnonymizeIP,
		})
		return res, err
	})
	if err := app.Run(); err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntimeError
	}
	return exitOK
}

func parseArgs(args []string, stdout, stderr io.Writer) (config, int, error) {
	var cfg config
	if len(args) > 0 && args[0] == "analyze" {
		args = args[1:]
	}

	fs := flag.NewFlagSet("nora", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&cfg.format, "format", "text", "output format: text or json")
	fs.IntVar(&cfg.top, "top", 10, "number of top items to show")
	since := fs.String("since", "", "include records at or after timestamp")
	until := fs.String("until", "", "include records at or before timestamp")
	fs.BoolVar(&cfg.anonymizeIP, "anonymize-ip", false, "mask client IP addresses")
	fs.BoolVar(&cfg.quiet, "quiet", false, "suppress report output")
	fs.StringVar(&cfg.configPath, "config", "nora.config.json", "config file path")
	fs.StringVar(&cfg.targetName, "target", "", "remote target name from config")
	fs.BoolVar(&cfg.listTargets, "list-targets", false, "list remote targets from config")
	fs.StringVar(&cfg.ssh.host, "ssh-host", "", "SSH host or config alias to read the log from")
	fs.StringVar(&cfg.ssh.user, "ssh-user", "", "SSH username")
	fs.IntVar(&cfg.ssh.port, "ssh-port", 0, "SSH port")
	fs.StringVar(&cfg.ssh.identity, "ssh-identity", "", "SSH identity file")
	fs.BoolVar(&cfg.ssh.sudo, "ssh-sudo", false, "read remote log through sudo cat")
	showVersion := fs.Bool("version", false, "print version")
	if err := fs.Parse(normalizeArgs(args)); err != nil {
		return cfg, exitInvalidArgs, err
	}
	if *showVersion {
		fmt.Fprintln(stdout, version)
		return cfg, exitOK, flag.ErrHelp
	}
	if cfg.listTargets {
		code, err := listTargets(stdout, cfg.configPath)
		return cfg, code, err
	}
	if cfg.format != "text" && cfg.format != "json" {
		return cfg, exitInvalidArgs, fmt.Errorf("invalid --format %q", cfg.format)
	}
	if cfg.top <= 0 {
		return cfg, exitInvalidArgs, fmt.Errorf("--top must be greater than zero")
	}
	var err error
	if *since != "" {
		cfg.since, err = parseTime(*since)
		if err != nil {
			return cfg, exitInvalidArgs, fmt.Errorf("invalid --since: %w", err)
		}
	}
	if *until != "" {
		cfg.until, err = parseTime(*until)
		if err != nil {
			return cfg, exitInvalidArgs, fmt.Errorf("invalid --until: %w", err)
		}
	}
	if cfg.targetName != "" {
		target, err := loadTarget(cfg.configPath, cfg.targetName)
		if err != nil {
			return cfg, exitInvalidArgs, err
		}
		applyTarget(&cfg, target)
	}
	if fs.NArg() > 1 {
		return cfg, exitInvalidArgs, fmt.Errorf("usage: nora analyze <path|-> [options]")
	}
	if fs.NArg() == 1 {
		cfg.path = fs.Arg(0)
	}
	if cfg.path == "" {
		return cfg, exitInvalidArgs, fmt.Errorf("usage: nora analyze <path|-> [options]")
	}
	return cfg, exitOK, nil
}

func listTargets(stdout io.Writer, path string) (int, error) {
	cfg, err := appconfig.Load(path)
	if err != nil {
		return exitInvalidArgs, err
	}
	for name, target := range cfg.RemoteTargets {
		sudo := ""
		if target.Sudo {
			sudo = " sudo"
		}
		fmt.Fprintf(stdout, "%s\t%s\t%s%s\n", name, target.Host, target.Path, sudo)
	}
	return exitOK, flag.ErrHelp
}

func loadTarget(path, name string) (appconfig.RemoteTarget, error) {
	cfg, err := appconfig.Load(path)
	if err != nil {
		return appconfig.RemoteTarget{}, err
	}
	return cfg.Target(name)
}

func applyTarget(cfg *config, target appconfig.RemoteTarget) {
	if cfg.ssh.host == "" {
		cfg.ssh.host = target.Host
	}
	if cfg.ssh.user == "" {
		cfg.ssh.user = target.User
	}
	if cfg.ssh.port == 0 {
		cfg.ssh.port = target.Port
	}
	if cfg.ssh.identity == "" {
		cfg.ssh.identity = target.Identity
	}
	if !cfg.ssh.sudo {
		cfg.ssh.sudo = target.Sudo
	}
	if cfg.path == "" {
		cfg.path = target.Path
	}
}

func normalizeArgs(args []string) []string {
	flags := make([]string, 0, len(args))
	positionals := make([]string, 0, 1)
	valueFlags := map[string]bool{
		"-format":        true,
		"--format":       true,
		"-top":           true,
		"--top":          true,
		"-since":         true,
		"--since":        true,
		"-until":         true,
		"--until":        true,
		"-config":        true,
		"--config":       true,
		"-target":        true,
		"--target":       true,
		"-ssh-host":      true,
		"--ssh-host":     true,
		"-ssh-user":      true,
		"--ssh-user":     true,
		"-ssh-port":      true,
		"--ssh-port":     true,
		"-ssh-identity":  true,
		"--ssh-identity": true,
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-" {
			positionals = append(positionals, arg)
			continue
		}
		if len(arg) > 0 && arg[0] == '-' {
			flags = append(flags, arg)
			if valueFlags[arg] && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		positionals = append(positionals, arg)
	}
	return append(flags, positionals...)
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

func openInput(path string, stdin io.Reader, sshCfg sshConfig) (io.Reader, func(), int, error) {
	if sshCfg.host != "" {
		return openSSHInput(path, sshCfg)
	}
	if path == "-" {
		return stdin, func() {}, exitOK, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, func() {}, exitOpenError, err
	}
	return f, func() { _ = f.Close() }, exitOK, nil
}

func openSSHInput(path string, cfg sshConfig) (io.Reader, func(), int, error) {
	if path == "-" {
		return nil, func() {}, exitInvalidArgs, fmt.Errorf("remote log path is required when --ssh-host is used")
	}
	args := sshArgs(path, cfg)
	cmd := exec.Command("ssh", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, func() {}, exitRuntimeError, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, func() {}, exitOpenError, err
	}
	closeFn := func() {
		_ = cmd.Wait()
	}
	return stdout, closeFn, exitOK, nil
}

func sshArgs(path string, cfg sshConfig) []string {
	args := []string{"-o", "BatchMode=yes"}
	if cfg.port > 0 {
		args = append(args, "-p", strconv.Itoa(cfg.port))
	}
	if cfg.identity != "" {
		args = append(args, "-i", cfg.identity)
	}
	host := cfg.host
	if cfg.user != "" {
		host = cfg.user + "@" + host
	}
	args = append(args, host)
	command := "cat -- " + shellQuote(path)
	if cfg.sudo {
		command = "sudo cat -- " + shellQuote(path)
	}
	args = append(args, command)
	return args
}

func shellQuote(value string) string {
	if value == "" {
		return "''"
	}
	out := "'"
	for _, r := range value {
		if r == '\'' {
			out += "'\\''"
			continue
		}
		out += string(r)
	}
	return out + "'"
}

func analyze(input io.Reader, cfg config) (analyzer.Result, int, error) {
	a := analyzer.New(analyzer.Options{
		Top:         cfg.top,
		Since:       cfg.since,
		Until:       cfg.until,
		AnonymizeIP: cfg.anonymizeIP,
	})

	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64*1024), 10*1024*1024)
	for scanner.Scan() {
		rec, err := parser.Parse(scanner.Text())
		if err != nil {
			a.AddMalformed()
			continue
		}
		a.Add(rec)
	}
	if err := scanner.Err(); err != nil {
		return analyzer.Result{}, exitRuntimeError, err
	}
	res := a.Result()
	if res.ParsedLines == 0 && res.MalformedLines > 0 {
		return res, exitUnrecognized, fmt.Errorf("log format could not be recognized")
	}
	return res, exitOK, nil
}
