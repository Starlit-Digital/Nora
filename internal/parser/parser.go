package parser

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

var ErrMalformed = errors.New("malformed log line")

type Record struct {
	Client    string
	Time      time.Time
	Method    string
	Target    string
	Protocol  string
	Status    int
	Bytes     int64
	Referrer  string
	UserAgent string
}

func Parse(line string) (Record, error) {
	var rec Record
	fields, err := splitLogLine(line)
	if err != nil {
		return rec, err
	}
	if len(fields) != 7 && len(fields) != 9 {
		return rec, ErrMalformed
	}

	t, err := time.Parse("02/Jan/2006:15:04:05 -0700", fields[3])
	if err != nil {
		return rec, ErrMalformed
	}
	req := strings.Fields(fields[4])
	if len(req) != 3 {
		return rec, ErrMalformed
	}
	status, err := strconv.Atoi(fields[5])
	if err != nil {
		return rec, ErrMalformed
	}
	var bytes int64
	if fields[6] != "-" {
		bytes, err = strconv.ParseInt(fields[6], 10, 64)
		if err != nil {
			return rec, ErrMalformed
		}
	}

	rec = Record{
		Client:   fields[0],
		Time:     t,
		Method:   req[0],
		Target:   req[1],
		Protocol: req[2],
		Status:   status,
		Bytes:    bytes,
	}
	if len(fields) == 9 {
		rec.Referrer = fields[7]
		rec.UserAgent = fields[8]
	}
	return rec, nil
}

func splitLogLine(line string) ([]string, error) {
	fields := make([]string, 0, 9)
	for i := 0; i < len(line); {
		for i < len(line) && line[i] == ' ' {
			i++
		}
		if i >= len(line) {
			break
		}
		switch line[i] {
		case '[':
			end := strings.IndexByte(line[i+1:], ']')
			if end < 0 {
				return nil, ErrMalformed
			}
			fields = append(fields, line[i+1:i+1+end])
			i += end + 2
		case '"':
			value, next, err := readQuoted(line, i)
			if err != nil {
				return nil, err
			}
			fields = append(fields, value)
			i = next
		default:
			start := i
			for i < len(line) && line[i] != ' ' {
				i++
			}
			fields = append(fields, line[start:i])
		}
	}
	return fields, nil
}

func readQuoted(line string, start int) (string, int, error) {
	var b strings.Builder
	escaped := false
	for i := start + 1; i < len(line); i++ {
		c := line[i]
		if escaped {
			b.WriteByte(c)
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if c == '"' {
			return b.String(), i + 1, nil
		}
		b.WriteByte(c)
	}
	return "", 0, ErrMalformed
}
