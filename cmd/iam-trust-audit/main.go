package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"iam-trust-audit/internal/parse"
	"iam-trust-audit/internal/report"
	"iam-trust-audit/internal/rules"
)

func main() {
	format := flag.String("format", "text", "text or json")
	failOn := flag.String("fail-on", "low", "exit non-zero at this severity or above: low, medium, high")
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: iam-trust-audit [--format text|json] [--fail-on low|medium|high] file...")
		os.Exit(2)
	}
	level := strings.ToLower(strings.TrimSpace(*failOn))
	switch level {
	case "low", "medium", "high":
	default:
		fmt.Fprintln(os.Stderr, "fail-on must be low, medium, or high")
		os.Exit(2)
	}
	var policies []parse.Policy
	for _, path := range flag.Args() {
		parsed, err := parse.ReadFile(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		policies = append(policies, parsed...)
	}
	findings := rules.Evaluate(policies)
	var err error
	if *format == "json" {
		err = report.JSON(os.Stdout, findings, level)
	} else if *format == "text" {
		err = report.Text(os.Stdout, findings)
	} else {
		fmt.Fprintln(os.Stderr, "format must be text or json")
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if report.Exceeds(findings, level) {
		os.Exit(1)
	}
}
