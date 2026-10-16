package plugins

import (
	"embed"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ruleFile is the on-disk YAML/JSON shape.
type ruleFile struct {
	Rules []*Rule `yaml:"rules" json:"rules"`
}

// LoadRules parses rules from YAML/JSON bytes.
func LoadRules(data []byte) ([]*Rule, error) {
	var f ruleFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	return f.Rules, nil
}

// LoadRulesFile reads and parses a rules file.
func LoadRulesFile(path string) ([]*Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return LoadRules(data)
}

// SaveRulesFile writes rules to a YAML file.
func SaveRulesFile(path string, rules []*Rule) error {
	data, err := MarshalRulesYAML(rules)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// MarshalRulesYAML serializes rules to YAML bytes.
func MarshalRulesYAML(rules []*Rule) ([]byte, error) {
	return yaml.Marshal(ruleFile{Rules: rules})
}

// LoadDefault loads embedded built-in rules (see rules/default.yaml).
func LoadDefault(fs embed.FS, path string) ([]*Rule, error) {
	data, err := fs.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read embedded rules %s: %w", path, err)
	}
	return LoadRules(data)
}

// RuleToMap converts a rule to a generic map for JSON APIs (without the
// compiled regex). Useful for the rule-management UI.
func RuleToMap(r *Rule) map[string]any {
	return map[string]any{
		"id":          r.ID,
		"name":        r.Name,
		"severity":    r.Severity,
		"category":    r.Category,
		"scope":       r.Scope,
		"pattern":     r.Pattern,
		"headerName":  r.HeaderName,
		"validator":   r.Validator,
		"context":     r.Context,
		"maskValue":   r.MaskValue,
		"minEntropy":  r.MinEntropy,
		"description": r.Description,
		"enabled":     r.IsEnabled(),
	}
}

// MapToRule converts a generic map (from JSON) back to a Rule.
func MapToRule(m map[string]any) *Rule {
	getStr := func(k string) string {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
		return ""
	}
	getBool := func(k string) bool {
		if v, ok := m[k]; ok {
			if b, ok := v.(bool); ok {
				return b
			}
		}
		return true
	}
	getInt := func(k string) int {
		if v, ok := m[k]; ok {
			switch n := v.(type) {
			case int:
				return n
			case float64:
				return int(n)
			}
		}
		return 0
	}
	getFloat := func(k string) float64 {
		if v, ok := m[k]; ok {
			if f, ok := v.(float64); ok {
				return f
			}
		}
		return 0
	}
	scope := []string{}
	if v, ok := m["scope"]; ok {
		if arr, ok := v.([]any); ok {
			for _, s := range arr {
				if str, ok := s.(string); ok {
					scope = append(scope, str)
				}
			}
		}
	}
	enabled := getBool("enabled")
	return &Rule{
		ID:          getStr("id"),
		Name:        getStr("name"),
		Severity:    getStr("severity"),
		Category:    getStr("category"),
		Scope:       scope,
		Pattern:     getStr("pattern"),
		HeaderName:  getStr("headerName"),
		Validator:   getStr("validator"),
		Context:     getInt("context"),
		MaskValue:   getBool("maskValue"),
		MinEntropy:  getFloat("minEntropy"),
		Description: getStr("description"),
		Enabled:     &enabled,
	}
}
