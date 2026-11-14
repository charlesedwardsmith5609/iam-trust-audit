// Package parse reads IAM trust policy JSON and Terraform heredocs.
// It does not parse jsonencode HCL.
package parse

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"
	"syscall"
)

const (
	MaxBytes = 1 << 20
	maxDepth = 64
)

// readBounded opens path once, refuses anything but a regular file, and reads at
// most MaxBytes. O_NOFOLLOW rejects a symlink as the last component; O_NONBLOCK
// keeps open from hanging on a FIFO.
func readBounded(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%q is not a regular file", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxBytes {
		return nil, fmt.Errorf("%q is larger than %d bytes", path, MaxBytes)
	}
	return b, nil
}

// checkJSON walks data once with a Decoder. It rejects duplicate object keys and
// nesting deeper than maxDepth.
func checkJSON(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	type frame struct {
		object  bool
		keys    map[string]bool
		wantKey bool
	}
	var stack []frame
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if n := len(stack); n > 0 && stack[n-1].object && stack[n-1].wantKey && tok != json.Delim('}') {
			key, ok := tok.(string)
			if !ok {
				return fmt.Errorf("invalid object key %v", tok)
			}
			if stack[n-1].keys[key] {
				return fmt.Errorf("duplicate key %q", key)
			}
			stack[n-1].keys[key] = true
			stack[n-1].wantKey = false
			continue
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				if len(stack) >= maxDepth {
					return fmt.Errorf("JSON nested deeper than %d levels", maxDepth)
				}
				stack = append(stack, frame{object: d == '{', keys: map[string]bool{}, wantKey: d == '{'})
				continue
			default:
				stack = stack[:len(stack)-1]
			}
		}
		// A value (scalar or closed container) ended; the next token in an object is a key.
		if n := len(stack); n > 0 && stack[n-1].object {
			stack[n-1].wantKey = true
		}
	}
}

// Statement is one trust statement with condition values flattened to strings.
type Statement struct {
	Index         int
	Effect        string
	Actions       []string
	NotActions    []string
	Principals    []Principal
	NotPrincipals []Principal
	Conditions    []Condition
}

// Condition is one operator/key pair with its values, in file order. Operator is as written.
type Condition struct {
	Operator string
	Key      string
	Values   []string
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

// decodeEncoded percent-decodes a document that starts with an encoded "{".
// url.PathUnescape is used so that "+" stays a plus sign.
func decodeEncoded(data []byte) ([]byte, error) {
	if len(data) >= 3 && strings.EqualFold(string(data[:3]), "%7B") {
		text, err := url.PathUnescape(string(data))
		if err != nil {
			return nil, fmt.Errorf("invalid percent-encoding: %w", err)
		}
		return []byte(text), nil
	}
	return data, nil
}

type rawDoc struct {
	Role                     json.RawMessage `json:"Role"`
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

// ReadFile loads path. Non-regular files (including a symlink as the last path
// component) and files over MaxBytes are errors.
func ReadFile(path string) ([]Policy, error) {
	data, err := readBounded(path)
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

// ParseJSON parses a trust policy, an `aws iam get-role` document ({"Role":
// {"AssumeRolePolicyDocument": ...}}), a role wrapper with AssumeRolePolicyDocument,
// or a percent-encoded policy. The document may be an object or a JSON string.
// Errors do not name the file; ReadFile adds the path once.
func ParseJSON(file string, data []byte) (Policy, error) {
	data, err := decodeEncoded(bytes.TrimSpace(data))
	if err != nil {
		return Policy{}, err
	}
	if err := checkJSON(data); err != nil {
		return Policy{}, fmt.Errorf("invalid JSON: %w", err)
	}
	var probe rawDoc
	if err := json.Unmarshal(data, &probe); err != nil {
		return Policy{}, fmt.Errorf("invalid JSON: %w", err)
	}
	if len(probe.Statement) == 0 && len(probe.Role) > 0 {
		data = probe.Role
		probe = rawDoc{}
		if err := json.Unmarshal(data, &probe); err != nil {
			return Policy{}, fmt.Errorf("invalid JSON in Role: %w", err)
		}
	}
	body := data
	if len(probe.Statement) == 0 && len(probe.AssumeRolePolicyDocument) > 0 {
		body = probe.AssumeRolePolicyDocument
		if len(body) > 0 && body[0] == '"' {
			var encoded string
			if err := json.Unmarshal(body, &encoded); err != nil {
				return Policy{}, err
			}
			body, err = decodeEncoded([]byte(strings.TrimSpace(encoded)))
			if err != nil {
				return Policy{}, err
			}
		}
	}
	var doc struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return Policy{}, fmt.Errorf("invalid JSON: %w", err)
	}
	if err := checkJSON(body); err != nil {
		return Policy{}, fmt.Errorf("invalid JSON: %w", err)
	}
	if len(doc.Statement) == 0 || string(doc.Statement) == "null" {
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
	if len(many) == 0 {
		return Policy{}, fmt.Errorf("trust policy has an empty Statement")
	}
	out := Policy{File: file}
	for i, raw := range many {
		if len(raw.Effect)+len(raw.Action)+len(raw.NotAction)+len(raw.Principal)+len(raw.NotPrincipal)+len(raw.Condition) == 0 {
			return Policy{}, fmt.Errorf("statement %d is empty", i)
		}
		actions, err := stringList(raw.Action, true)
		if err != nil {
			return Policy{}, fmt.Errorf("statement %d Action: %w", i, err)
		}
		notActions, err := stringList(raw.NotAction, true)
		if err != nil {
			return Policy{}, fmt.Errorf("statement %d NotAction: %w", i, err)
		}
		conds, err := conditions(raw.Condition)
		if err != nil {
			return Policy{}, fmt.Errorf("statement %d Condition: %w", i, err)
		}
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
			Actions:       actions,
			NotActions:    notActions,
			Principals:    princ,
			NotPrincipals: notPrinc,
			Conditions:    conds,
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

// stringList decodes a string, or a list of strings, as text. Unless onlyStrings
// is set, numbers and bools are also accepted (condition values).
func stringList(raw json.RawMessage, onlyStrings bool) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	value, err := decodeValue(raw)
	if err != nil {
		return nil, err
	}
	switch v := value.(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			text, ok := scalarText(item, onlyStrings)
			if !ok {
				return nil, fmt.Errorf("list entry %v is not a string, number or bool", item)
			}
			out = append(out, text)
		}
		return out, nil
	default:
		text, ok := scalarText(v, onlyStrings)
		if !ok {
			return nil, fmt.Errorf("value %s is not a string, number, bool or list", string(raw))
		}
		return []string{text}, nil
	}
}

func scalarText(v any, onlyStrings bool) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	}
	if onlyStrings {
		return "", false
	}
	switch x := v.(type) {
	case json.Number:
		return x.String(), true
	case bool:
		return fmt.Sprint(x), true
	}
	return "", false
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
	case []any:
		items, err := principalItems(v)
		if err != nil {
			return nil, err
		}
		var out []Principal
		for _, item := range items {
			if item == "*" {
				out = append(out, Principal{Kind: "Any", Value: "*"})
			} else {
				out = append(out, Principal{Kind: "AWS", Value: item})
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("principal must be a string, a list or an object, got %s", string(raw))
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

// orderedObject returns the members of a JSON object in file order.
func orderedObject(raw json.RawMessage) ([]string, []json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil {
		return nil, nil, err
	} else if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, nil, fmt.Errorf("expected an object, got %s", string(raw))
	}
	var keys []string
	var values []json.RawMessage
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, nil, err
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, nil, err
		}
		keys = append(keys, tok.(string))
		values = append(values, value)
	}
	return keys, values, nil
}

func conditions(raw json.RawMessage) ([]Condition, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	ops, opBodies, err := orderedObject(raw)
	if err != nil {
		return nil, err
	}
	var out []Condition
	for i, op := range ops {
		keys, bodies, err := orderedObject(opBodies[i])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		for j, key := range keys {
			values, err := stringList(bodies[j], false)
			if err != nil {
				return nil, fmt.Errorf("%s %s: %w", op, key, err)
			}
			out = append(out, Condition{Operator: op, Key: key, Values: values})
		}
	}
	return out, nil
}
