package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
)

const ignoredLawOfDemeter = "[Design Principles: Law of Demeter]"

type diagnostic struct {
	Position string `json:"posn"`
	Message  string `json:"message"`
}

func main() {
	packages := os.Args[1:]
	if len(packages) == 0 {
		packages = []string{"./..."}
	}

	args := append([]string{"lint", "-json"}, packages...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command := exec.CommandContext(context.Background(), "gojgp", args...)
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		_, _ = os.Stderr.Write(stderr.Bytes())
		fmt.Fprintf(os.Stderr, "run gojgp: %v\n", err)
		os.Exit(1)
	}

	var report map[string]map[string][]diagnostic
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		fmt.Fprintf(os.Stderr, "decode gojgp output: %v\n", err)
		os.Exit(1)
	}

	seen := make(map[string]struct{})
	var findings []diagnostic
	for _, analyzers := range report {
		for _, finding := range analyzers["gojgp"] {
			if strings.HasPrefix(finding.Message, ignoredLawOfDemeter) {
				continue
			}
			key := finding.Position + "\x00" + finding.Message
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			findings = append(findings, finding)
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Position != findings[j].Position {
			return findings[i].Position < findings[j].Position
		}
		return findings[i].Message < findings[j].Message
	})
	for _, finding := range findings {
		fmt.Fprintf(os.Stderr, "%s: %s\n", finding.Position, finding.Message)
	}
	if len(findings) != 0 {
		fmt.Fprintf(os.Stderr, "gojgp: %d issue(s)\n", len(findings))
		os.Exit(1)
	}
}
