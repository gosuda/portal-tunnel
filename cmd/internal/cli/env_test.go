package cli

import (
	"flag"
	"runtime"
	"testing"
)

func TestEnvironmentResolutionIsIndependent(t *testing.T) {
	first := NewEnv([]string{"DISCOVERY=invalid", "AWS_REGION=us-east-1", "AWS_DEFAULT_REGION=ap-northeast-2"})
	second := NewEnv([]string{"DISCOVERY=true", "AWS_DEFAULT_REGION=eu-west-1"})
	var firstDiscovery, secondDiscovery bool
	var firstRegion, secondRegion string
	firstFlags := flag.NewFlagSet("first", flag.ContinueOnError)
	secondFlags := flag.NewFlagSet("second", flag.ContinueOnError)
	first.Bool(firstFlags, &firstDiscovery, "discovery", false, "discovery", "DISCOVERY")
	second.Bool(secondFlags, &secondDiscovery, "discovery", false, "discovery", "DISCOVERY")
	first.String(firstFlags, &firstRegion, "region", "default", "region", "AWS_REGION", "AWS_DEFAULT_REGION")
	second.String(secondFlags, &secondRegion, "region", "default", "region", "AWS_REGION", "AWS_DEFAULT_REGION")
	if firstDiscovery || !secondDiscovery || firstRegion != "us-east-1" || secondRegion != "eu-west-1" {
		t.Fatalf("environment values crossed resolutions: %v, %v, %q, %q", firstDiscovery, secondDiscovery, firstRegion, secondRegion)
	}
	if len(first.Issues) != 1 || len(second.Issues) != 0 || len(first.Vars) != 2 || len(second.Vars) != 2 {
		t.Fatal("resolution diagnostics crossed environments")
	}
	if first.Vars[1].SetBy != "AWS_REGION" || second.Vars[1].SetBy != "AWS_DEFAULT_REGION" {
		t.Fatal("alias precedence or provenance was lost")
	}
	if err := firstFlags.Parse([]string{"--region=from-flag"}); err != nil {
		t.Fatal(err)
	}
	if firstRegion != "from-flag" || secondRegion != "eu-west-1" {
		t.Fatal("flags did not override only their own environment")
	}
}

func TestEnvironmentInputIsCaptured(t *testing.T) {
	input := []string{"NAME=before"}
	env := NewEnv(input)
	input[0] = "NAME=after"
	var value string
	env.String(flag.NewFlagSet("capture", flag.ContinueOnError), &value, "name", "default", "name", "NAME")
	if value != "before" {
		t.Fatalf("captured environment changed with its input: %q", value)
	}
}

func TestWindowsEnvironmentNamesRemainCaseInsensitive(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows environment name semantics")
	}
	env := NewEnv([]string{"name=first", "NAME=last"})
	var value string
	env.String(flag.NewFlagSet("windows", flag.ContinueOnError), &value, "name", "default", "name", "Name")
	if value != "last" {
		t.Fatalf("case-insensitive environment resolution = %q, want last", value)
	}
}
