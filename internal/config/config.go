package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type File struct {
	RemoteTargets map[string]RemoteTarget `json:"remote_targets"`
}

type RemoteTarget struct {
	Host     string `json:"host"`
	User     string `json:"user,omitempty"`
	Port     int    `json:"port,omitempty"`
	Identity string `json:"identity,omitempty"`
	Path     string `json:"path"`
	Sudo     bool   `json:"sudo,omitempty"`
}

func Load(path string) (File, error) {
	var cfg File
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (f File) Target(name string) (RemoteTarget, error) {
	target, ok := f.RemoteTargets[name]
	if !ok {
		return RemoteTarget{}, fmt.Errorf("remote target %q not found", name)
	}
	if target.Host == "" {
		return RemoteTarget{}, fmt.Errorf("remote target %q is missing host", name)
	}
	if target.Path == "" {
		return RemoteTarget{}, fmt.Errorf("remote target %q is missing path", name)
	}
	return target, nil
}
