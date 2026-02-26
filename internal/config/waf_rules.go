package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type RuleConfig struct {
	ID      string `yaml:"id"`
	Pattern string `yaml:"pattern"`
}

type WAFRulesConfig struct {
	Mode string       `yaml:"mode"` // "block" or "audit"
	SQLi []RuleConfig `yaml:"sqli"`
	XSS  []RuleConfig `yaml:"xss"`
}

type CompiledRule struct {
	ID string
	RE *regexp.Regexp
}

type CompiledWAFRules struct {
	Mode string
	SQLi []CompiledRule
	XSS  []CompiledRule
}

func LoadWAFRules(path string) (*CompiledWAFRules, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rules file: %w", err)
	}

	var cfg WAFRulesConfig
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}

	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if mode == "" {
		mode = "block"
	}
	if mode != "block" && mode != "audit" {
		return nil, fmt.Errorf("invalid mode %q (must be block or audit)", cfg.Mode)
	}

	compiled := &CompiledWAFRules{
		Mode: mode,
		SQLi: make([]CompiledRule, 0, len(cfg.SQLi)),
		XSS:  make([]CompiledRule, 0, len(cfg.XSS)),
	}

	for _, r := range cfg.SQLi {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("compile sqli rule %q: %w", r.ID, err)
		}
		compiled.SQLi = append(compiled.SQLi, CompiledRule{ID: r.ID, RE: re})
	}

	for _, r := range cfg.XSS {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("compile xss rule %q: %w", r.ID, err)
		}
		compiled.XSS = append(compiled.XSS, CompiledRule{ID: r.ID, RE: re})
	}

	if len(compiled.SQLi) == 0 && len(compiled.XSS) == 0 {
		return nil, fmt.Errorf("no rules loaded from %s", path)
	}

	return compiled, nil
}
