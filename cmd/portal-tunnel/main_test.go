package main

import (
	"flag"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

func TestExposeFlags(t *testing.T) {
	utils.ResetEnvRegistry()
	t.Cleanup(utils.ResetEnvRegistry)
	for _, name := range []string{"UDP_ENABLED", "TCP_ENABLED", "OVERLAY_ENABLED", "BAN_MITM"} {
		t.Setenv(name, "true")
	}
	flags := exposeFlags{}
	fs := flag.NewFlagSet("expose", flag.ContinueOnError)
	registerExposeFlags(fs, &flags)
	if flags.Discovery == nil || !*flags.Discovery {
		t.Fatal("discovery must default to enabled")
	}
	if !*flags.BanMITM || !flags.UDPEnabled || !flags.TCPEnabled || !flags.Overlay {
		t.Fatal("transport flags must inherit environment defaults")
	}
	if err := fs.Parse([]string{
		"--discovery=false", "--ban-mitm=false", "--udp=false", "--tcp=false",
		"--overlay=false", "--serve=./dist", "--cache", "--cache-ttl=5m",
		"--name=site", "--identity-path=site.json", "--max-active-relays=5",
		"--description=example",
	}); err != nil {
		t.Fatal(err)
	}
	if *flags.Discovery || *flags.BanMITM || flags.UDPEnabled || flags.TCPEnabled || flags.Overlay {
		t.Fatal("explicit false transport flags must override defaults and environment")
	}
	if flags.Serve != "./dist" || !flags.Cache || flags.CacheTTL != 5*time.Minute {
		t.Fatal("static flags did not populate the tunnel config")
	}
	if flags.Name != "site" || flags.IdentityPath != "site.json" || flags.MaxActiveRelays != 5 {
		t.Fatal("identity and relay flags did not populate the tunnel config")
	}
	if err := flags.Validate(); err != nil {
		t.Fatal(err)
	}
}
