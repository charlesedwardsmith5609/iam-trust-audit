// Package parse reads IAM trust policy JSON and Terraform heredocs.
// It does not parse jsonencode HCL.
package parse

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

const MaxBytes = 1 << 20

// Statement is one trust statement with condition values flattened to strings.
type Statement struct {
	Index      int
	Effect     string
	Actions    []string
	Principals []Principal
	Conditions map[string]map[string][]string
}

// Principal is one principal entry. Kind Any means the principal was "*".
type Principal struct {
	Kind  string
	Value string
}

// Policy is the trust document from one file.
type Policy struct {
	File       string
	Statements []Statement
}

type rawDoc struct {
	Statement                json.RawMessage `json:"Statement"`
	AssumeRolePolicyDocument json.RawMessage `json:"AssumeRolePolicyDocument"`
}

type rawStatement struct {
	Effect    string          `json:"Effect"`
	Action    json.RawMessage `json:"Action"`
	Principal json.RawMessage `json:"Principal"`
	Condition json.RawMessage `json:"Condition"`
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
		body, ok := heredocJSON(data)
		if !ok {
			return nil, nil
		}
		policy, err := ParseJSON(path, body)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		return []Policy{policy}, nil
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
		out.Statements = append(out.Statements, Statement{
			Index:      i,
			Effect:     raw.Effect,
			Actions:    stringList(raw.Action),
			Principals: principals(raw.Principal),
			Conditions: conditions(raw.Condition),
		})
	}
	return out, nil
}

func heredocJSON(data []byte) ([]byte, bool) {
	text := string(data)
	key := strings.Index(text, "assume_role_policy")
	if key < 0 {
		return nil, false
	}
	rest := text[key:]
	marker := strings.Index(rest, "<<")
	if marker < 0 {
		return nil, false
	}
	line := rest[marker+2:]
	line = strings.TrimLeft(line, "- \t")
	end := strings.IndexAny(line, "\r\n")
	if end < 0 {
		return nil, false
	}
	name := strings.TrimSpace(line[:end])
	body := line[end+1:]
	stop := "\n" + name
	at := strings.Index(body, stop)
	if at < 0 {
		return nil, false
	}
	return []byte(strings.TrimSpace(body[:at])), true
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

func principals(raw json.RawMessage) []Principal {
	if len(raw) == 0 {
		return nil
	}
	var star string
	if err := json.Unmarshal(raw, &star); err == nil {
		if star == "*" {
			return []Principal{{Kind: "Any", Value: "*"}}
		}
		return []Principal{{Kind: "AWS", Value: star}}
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil
	}
	var out []Principal
	for kind, value := range obj {
		for _, item := range stringList(value) {
			k := kind
			if item == "*" {
				k = "Any"
			}
			out = append(out, Principal{Kind: k, Value: item})
		}
	}
	return out
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
