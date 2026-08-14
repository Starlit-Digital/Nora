package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunAnalyzeStdinJSON(t *testing.T) {
	input := strings.NewReader(`127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /index.html?q=1 HTTP/1.1" 200 2326` + "\n")
	var stdout, stderr bytes.Buffer
	code := run([]string{"analyze", "-", "--format", "json"}, &stdout, &stderr, input)
	if code != exitOK {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"total_requests": 1`) || !strings.Contains(stdout.String(), `"/index.html"`) {
		t.Fatalf("unexpected stdout:\n%s", stdout.String())
	}
}

func TestRunInvalidArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"analyze", "-", "--format", "xml"}, &stdout, &stderr, strings.NewReader(""))
	if code != exitInvalidArgs {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
}

func TestSSHArgs(t *testing.T) {
	args := sshArgs("/var/log/nginx/access log's.log", sshConfig{
		host:     "pct",
		user:     "deploy",
		port:     2222,
		identity: "/tmp/key",
		sudo:     true,
	})
	got := strings.Join(args, " ")
	for _, want := range []string{
		"-o BatchMode=yes",
		"-p 2222",
		"-i /tmp/key",
		"deploy@pct",
		"sudo cat -- '/var/log/nginx/access log'\\''s.log'",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("ssh args missing %q: %q", want, got)
		}
	}
}

func TestTargetConfigCanProvidePathAndSSH(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "nora.config.json")
	err := os.WriteFile(configPath, []byte(`{
  "remote_targets": {
    "prod": {
      "host": "paycal-prod",
      "path": "/var/log/nginx/access.log",
      "sudo": true
    }
  }
}`), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	cfg, code, err := parseArgs([]string{"analyze", "--target", "prod", "--config", configPath}, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if code != exitOK || cfg.path != "/var/log/nginx/access.log" || cfg.ssh.host != "paycal-prod" || !cfg.ssh.sudo {
		t.Fatalf("unexpected config: code=%d cfg=%+v", code, cfg)
	}
}

func TestMissingTargetConfigReturnsInvalidArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"analyze", "--target", "missing", "--config", "does-not-exist.json"}, &stdout, &stderr, strings.NewReader(""))
	if code != exitInvalidArgs {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
}
