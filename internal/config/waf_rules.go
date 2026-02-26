package config

import (
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

type RuleConfig struct {
	ID      string `yaml:"id"`
	Pattern string `yaml:"pattern"`
}

type WAFRulesConfig struct {
	SQLi []RuleConfig `yaml:"sqli"`
	XSS  []RuleConfig `yaml:"xss"`
}

type CompiledRule struct {
	ID string
	RE *regexp.Regexp
}

type CompiledWAFRules struct {
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

	compiled := &CompiledWAFRules{
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
