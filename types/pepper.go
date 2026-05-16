package types

const (
	PepperModeDisabled = ""
	PepperModePassive  = "passive"
	PepperModeActive   = "active"
)

const (
	ErrPepperPFSHandshakeFailed        = "ERR_PFS_HANDSHAKE_FAILED"
	ErrPepperOnionIntegrityVoid        = "ERR_ONION_INTEGRITY_VOID"
	ErrPepperEntropyLow                = "ERR_PEPPER_ENTROPY_LOW"
	ErrPepperStaticEntry               = "ERR_PEPPER_STATIC_ENTRY"
	ErrPepperStaticIdentity            = "ERR_PEPPER_STATIC_IDENTITY"
	ErrPepperCircuitResetIntegrityVoid = "ERR_CIRCUIT_RESET_INTEGRITY_VOID"
)

const DefaultPepperMinEntropyBits = 256

// Circuit is the opaque handle for an active pepper circuit.
type Circuit interface {
	ID() uint64
	SessionKey() []byte
	PublicKey() [32]byte
	Close() error
}

// PepperProvider encapsulates pepper active-mode operations so that
// consumers (such as the SDK) do not need to import the concrete pepper package.
type PepperProvider interface {
	NewCircuit() (Circuit, error)
	ValidatePolicy(multiHopDepth int, explicitPath []string, discovery bool, identityJSON string) error
	RequireEntropy(minBits int) error
}
