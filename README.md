# NORA

NORA is a local-first CLI for NGINX Observability and Request Analytics.

It analyzes NGINX access logs as a stream and reports request volume, bandwidth,
status codes, methods, top paths, clients, referrers, user agents, and hourly
traffic.

## Usage

```sh
nora analyze /var/log/nginx/access.log
nora analyze access.log --format json
nora analyze access.log --top 20
cat access.log | nora analyze -
nora /var/log/nginx/access.log
nora analyze /var/log/nginx/access.log --ssh-host pct
nora analyze /var/log/nginx/access.log --ssh-host paycal-prod --ssh-sudo --format json > report.json
nora analyze --target paycal-prod-nginx-access --format json > report.json
nora analyze --list-targets
nora tui
```

## Options

```text
--format text|json
--top <number>
--since <timestamp>
--until <timestamp>
--anonymize-ip
--quiet
--config <path>
--target <name>
--list-targets
--ssh-host <host>
--ssh-user <user>
--ssh-port <port>
--ssh-identity <path>
--ssh-sudo
--help
--version
```

Timestamps accept RFC3339 values or NGINX timestamps such as
`10/Oct/2000:13:55:36 -0700`.

NORA never transmits log data, performs DNS or geolocation lookups, or evaluates
log contents.

When `--ssh-host` is used, NORA logs in with the local `ssh` command, streams the
remote log file through stdout, and performs all parsing, aggregation, and report
generation locally.

Remote targets can be stored in `nora.config.json`:

```json
{
  "remote_targets": {
    "paycal-prod-nginx-access": {
      "host": "paycal-prod",
      "path": "/var/log/nginx/access.log"
    }
  }
}
```

Targets should use SSH config aliases or key paths. Do not store passwords in the
config file.

## TUI

Run `nora tui` to select a configured remote target, apply basic filters, run the
analysis locally from the remote SSH stream, and drill into summary, status,
method, path, client, referrer, user-agent, hourly, full text, or JSON-export
views.

## License

NORA is open source under the 0BSD license. See [LICENSE](LICENSE).
