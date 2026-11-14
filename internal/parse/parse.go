// Package parse reads IAM trust policy JSON and Terraform heredocs.
// It does not parse jsonencode HCL.
package parse

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

const MaxBytes = 1 << 20

// Statement is one trust statement with condition values flattened to strings.
type Statement struct {
	Index         int
	Effect        string
	Actions       []string
	NotActions    []string
	Principals    []Principal
	NotPrincipals []Principal
	Conditions    map[string]map[string][]string
}

// Principal is one principal entry. Kind Any means the principal was "*".
type Principal struct {
	Kind  string
	Value string
}

// Policy is the trust document from one file.
type Policy struct {
	File       string
	Label      string
	Statements []Statement
	Unparsed   []Unparsed
}

// Unparsed marks a .tf assume_role_policy that could not be read as a JSON heredoc.
type Unparsed struct {
	Line   int
	Reason string
}

type rawDoc struct {
	Statement                json.RawMessage `json:"Statement"`
	AssumeRolePolicyDocument json.RawMessage `json:"AssumeRolePolicyDocument"`
}

type rawStatement struct {
	Effect       string          `json:"Effect"`
	Action       json.RawMessage `json:"Action"`
	NotAction    json.RawMessage `json:"NotAction"`
	Principal    json.RawMessage `json:"Principal"`
	NotPrincipal json.RawMessage `json:"NotPrincipal"`
	Condition    json.RawMessage `json:"Condition"`
}

// ReadFile loads path. Symlinks and files over MaxBytes are errors.
func ReadFile(path string) ([]Policy, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is a symlink", path)
	}
	if info.Size() > MaxBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, MaxBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if strings.HasSuffix(strings.ToLower(path), ".tf") {
		var out []Policy
		for _, found := range findAssumeRolePolicies(data) {
			if found.Reason != "" {
				out = append(out, Policy{File: path, Label: found.Label, Unparsed: []Unparsed{{Line: found.Line, Reason: found.Reason}}})
				continue
			}
			policy, err := ParseJSON(path, found.Body)
			if err != nil {
				return nil, fmt.Errorf("%s (%s): %w", path, found.Label, err)
			}
			policy.Label = found.Label
			out = append(out, policy)
		}
		return out, nil
	}
	policy, err := ParseJSON(path, data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return []Policy{policy}, nil
}

// ParseJSON parses a trust policy or a role wrapper with AssumeRolePolicyDocument.
func ParseJSON(file string, data []byte) (Policy, error) {
	data = bytes.TrimSpace(data)
	var probe rawDoc
	if err := json.Unmarshal(data, &probe); err != nil {
		return Policy{}, fmt.Errorf("invalid JSON: %w", err)
	}
	body := data
	if len(probe.Statement) == 0 && len(probe.AssumeRolePolicyDocument) > 0 {
		body = probe.AssumeRolePolicyDocument
		if len(body) > 0 && body[0] == '"' {
			var encoded string
			if err := json.Unmarshal(body, &encoded); err != nil {
				return Policy{}, err
			}
			body = []byte(encoded)
		}
	}
	var doc struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return Policy{}, fmt.Errorf("invalid JSON: %w", err)
	}
	if len(doc.Statement) == 0 {
		return Policy{}, fmt.Errorf("trust policy has no Statement")
	}
	var many []rawStatement
	if doc.Statement[0] == '[' {
		if err := json.Unmarshal(doc.Statement, &many); err != nil {
			return Policy{}, err
		}
	} else {
		var one rawStatement
		if err := json.Unmarshal(doc.Statement, &one); err != nil {
			return Policy{}, err
		}
		many = []rawStatement{one}
	}
	out := Policy{File: file}
	for i, raw := range many {
		princ, err := principals(raw.Principal)
		if err != nil {
			return Policy{}, fmt.Errorf("statement %d Principal: %w", i, err)
		}
		notPrinc, err := principals(raw.NotPrincipal)
		if err != nil {
			return Policy{}, fmt.Errorf("statement %d NotPrincipal: %w", i, err)
		}
		out.Statements = append(out.Statements, Statement{
			Index:         i,
			Effect:        raw.Effect,
			Actions:       stringList(raw.Action),
			NotActions:    stringList(raw.NotAction),
			Principals:    princ,
			NotPrincipals: notPrinc,
			Conditions:    conditions(raw.Condition),
		})
	}
	return out, nil
}

type tfPolicy struct {
	Line   int
	Label  string
	Body   []byte
	Reason string
}

// findAssumeRolePolicies scans line by line. Each assume_role_policy must open a
// heredoc on the same line; any other value form is reported with a Reason.
func findAssumeRolePolicies(data []byte) []tfPolicy {
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	var out []tfPolicy
	resource := ""
	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}
		if name, ok := resourceName(trimmed); ok {
			resource = name
		}
		at := strings.Index(trimmed, "assume_role_policy")
		if at < 0 {
			continue
		}
		rest := strings.TrimSpace(trimmed[at+len("assume_role_policy"):])
		if !strings.HasPrefix(rest, "=") {
			continue
		}
		rest = strings.TrimSpace(rest[1:])
		label := resource
		if label == "" {
			label = fmt.Sprintf("line %d", i+1)
		}
		item := tfPolicy{Line: i + 1, Label: label}
		if !strings.HasPrefix(rest, "<<") {
			item.Reason = "assume_role_policy is not a JSON heredoc (jsonencode, data source, string or other form)"
			out = append(out, item)
			continue
		}
		name := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(rest, "<<"), "-"))
		end := -1
		if name != "" {
			for j := i + 1; j < len(lines); j++ {
				if strings.TrimSpace(lines[j]) == name {
					end = j
					break
				}
			}
		}
		if end < 0 {
			item.Reason = "heredoc has no name or no terminator line"
			out = append(out, item)
			continue
		}
		item.Body = []byte(strings.TrimSpace(strings.Join(lines[i+1:end], "\n")))
		out = append(out, item)
		i = end
	}
	return out
}

// resourceName returns "type.name" for a line like: resource "aws_iam_role" "x" {
func resourceName(line string) (string, bool) {
	if !strings.HasPrefix(line, "resource") {
		return "", false
	}
	parts := strings.Split(line, `"`)
	if len(parts) < 4 {
		return "", false
	}
	return parts[1] + "." + parts[3], true
}

func stringList(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return []string{one}
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		return many
	}
	return nil
}

func principals(raw json.RawMessage) ([]Principal, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	value, err := decodeValue(raw)
	if err != nil {
		return nil, err
	}
	switch v := value.(type) {
	case string:
		if v == "*" {
			return []Principal{{Kind: "Any", Value: "*"}}, nil
		}
		return []Principal{{Kind: "AWS", Value: v}}, nil
	case map[string]any:
		kinds := make([]string, 0, len(v))
		for kind := range v {
			kinds = append(kinds, kind)
		}
		sort.Strings(kinds)
		var out []Principal
		for _, kind := range kinds {
			items, err := principalItems(v[kind])
			if err != nil {
				return nil, fmt.Errorf("%s: %w", kind, err)
			}
			for _, item := range items {
				k := kind
				if item == "*" {
					k = "Any"
				}
				out = append(out, Principal{Kind: k, Value: item})
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("principal must be a string or an object, got %s", string(raw))
}

func principalItems(value any) ([]string, error) {
	switch v := value.(type) {
	case string:
		return []string{v}, nil
	case json.Number:
		return []string{v.String()}, nil
	case []any:
		var out []string
		for _, item := range v {
			switch s := item.(type) {
			case string:
				out = append(out, s)
			case json.Number:
				out = append(out, s.String())
			default:
				return nil, fmt.Errorf("principal list entry %v is not a string or number", item)
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("principal value %v is not a string, number or list", value)
}

// decodeValue decodes JSON keeping numbers as their original text.
func decodeValue(raw json.RawMessage) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

func conditions(raw json.RawMessage) map[string]map[string][]string {
	if len(raw) == 0 {
		return nil
	}
	var ops map[string]map[string]json.RawMessage
	if err := json.Unmarshal(raw, &ops); err != nil {
		return nil
	}
	out := map[string]map[string][]string{}
	for op, keys := range ops {
		out[op] = map[string][]string{}
		for key, value := range keys {
			out[op][key] = stringList(value)
		}
	}
	return out
}
