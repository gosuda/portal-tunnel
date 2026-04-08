package types

// RelayState captures the last-known descriptor and local state for a relay
// observed through discovery.
type RelayState struct {
	Descriptor          RelayDescriptor
	Advertised          bool
	Expired             bool
	Banned              bool
	ConsecutiveFailures int
}
