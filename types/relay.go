package types

// RelayFailure classifies why a relay listener stopped.
type RelayFailure string

const (
	RelayFailureNone     RelayFailure = ""
	RelayFailureRuntime  RelayFailure = "runtime"
	RelayFailureTerminal RelayFailure = "terminal"
	RelayFailureMITM     RelayFailure = "mitm"
)
