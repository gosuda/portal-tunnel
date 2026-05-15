package utils

import (
	"net"
	"net/url"
	"strings"
)

var exposeNameOpeners = []string{
	"arcade", "bouncy", "bravo", "bubble", "candy", "cosmic", "dapper", "electric",
	"fancy", "fizzy", "flashy", "fuzzy", "gentle", "glitter", "golden", "happy",
	"hyper", "jazzy", "jolly", "lively", "lucky", "magic", "mellow", "minty",
	"misty", "moonlit", "mystic", "neon", "nova", "peppy", "pixel", "playful",
	"poppy", "rapid", "rocket", "rowdy", "snappy", "snazzy", "sparkly", "spicy",
	"sprightly", "starry", "sunny", "swift", "tangy", "tidy", "toasty", "turbo",
	"velvet", "vivid", "wavy", "whimsy", "wild", "wonky", "zany", "zesty",
}

var exposeNameCenters = []string{
	"alpaca", "badger", "banjo", "beacon", "biscuit", "capybara", "comet", "cricket",
	"dragon", "falcon", "feather", "fjord", "fox", "gadget", "gecko", "gizmo",
	"harbor", "heron", "iguana", "jelly", "koala", "lemur", "mango", "narwhal",
	"nebula", "noodle", "octopus", "otter", "panda", "pepper", "phoenix", "pickle",
	"puffin", "quokka", "radar", "ranger", "rocket", "scooter", "seahorse", "skylark",
	"sprocket", "starling", "sunbeam", "taco", "thimble", "tiger", "toucan", "triton",
	"walrus", "widget", "willow", "wombat", "yeti", "zeppelin", "zigzag", "zinnia",
}

var exposeNameClosers = []string{
	"arcade", "beacon", "boogie", "bounce", "burst", "cascade", "chorus", "dash",
	"disco", "drift", "echo", "fiesta", "flare", "flash", "flight", "flip",
	"glow", "groove", "jam", "jive", "launch", "loop", "march", "orbit",
	"parade", "party", "pulse", "quest", "rally", "riot", "ripple", "rodeo",
	"roll", "rush", "serenade", "shuffle", "signal", "sketch", "spark", "sprint",
	"starlight", "stride", "sway", "swoop", "twirl", "uplift", "vibe", "voyage",
	"whirl", "wink", "zap", "zenith", "zip", "zoom", "zest", "zone",
}

const (
	defaultExposeTargetPort = "3000"
	defaultExposeTargetHost = "127.0.0.1"
)

// DefaultExposeName generates a deterministic 3-word DNS label from a target
// address and seed using FNV-1a hashing. The algorithm matches the frontend
// implementation in frontend/src/lib/exposeName.ts:buildDefaultExposeName.
func DefaultExposeName(target, rawSeed string) (string, error) {
	seed := strings.TrimSpace(rawSeed)
	if cut, ok := strings.CutPrefix(seed, "cli_"); ok {
		seed = cut
	}
	if seed == "" {
		seed = "portal"
	}

	input := []byte(seed + "|" + normalizeExposeTarget(target))
	first := fnv1a32(input, 0x811c9dc5)
	second := fnv1a32(input, 0x9e3779b9)
	third := fnv1a32(input, 0x85ebca6b)

	label := strings.Join([]string{
		exposeNameOpeners[int(first&0xff)%len(exposeNameOpeners)],
		exposeNameCenters[int(second&0xff)%len(exposeNameCenters)],
		exposeNameClosers[int(third&0xff)%len(exposeNameClosers)],
	}, "-")

	return NormalizeDNSLabel(label)
}

// normalizeExposeTarget normalizes a target address for deterministic name
// generation. Must match frontend/src/lib/exposeName.ts:normalizeExposeTarget.
func normalizeExposeTarget(raw string) string {
	trimmed := strings.TrimSpace(raw)
	candidate := trimmed
	if candidate == "" {
		candidate = defaultExposeTargetPort
	}

	if isAllDigits(candidate) {
		return defaultExposeTargetHost + ":" + candidate
	}

	if strings.Contains(candidate, "://") {
		u, err := url.Parse(candidate)
		if err != nil {
			return candidate
		}
		if (u.Scheme == "http" || u.Scheme == "https") &&
			u.Host != "" &&
			(u.Path == "" || u.Path == "/") &&
			u.RawQuery == "" &&
			u.Fragment == "" {
			return u.Host
		}
		return candidate
	}

	u, err := url.Parse("tcp://" + candidate)
	if err != nil || u.Hostname() == "" {
		return candidate
	}
	port := u.Port()
	if port == "" {
		port = "80"
	}
	return net.JoinHostPort(u.Hostname(), port)
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func fnv1a32(data []byte, seed uint32) uint32 {
	h := seed
	for _, b := range data {
		h ^= uint32(b)
		h *= 0x01000193
	}
	return h
}
