package protocol

// HTTP header names and reverse-stream markers of the Portal wire protocol.
const (
	HeaderAccessToken       = "X-Portal-Access-Token"
	HeaderReverseCapability = "X-Portal-Reverse-Capability"
	HeaderXPayment          = "X-PAYMENT"
	HeaderPaymentSignature  = "PAYMENT-SIGNATURE"
	HeaderPaymentRequired   = "PAYMENT-REQUIRED"
	HeaderXPaymentRequired  = "X-PAYMENT-REQUIRED"
	HeaderPaymentResponse   = "PAYMENT-RESPONSE"
	HeaderXPaymentResponse  = "X-PAYMENT-RESPONSE"
	MarkerKeepalive         = byte(0x00)
	MarkerRawStart          = byte(0x01)
	MarkerTLSStart          = byte(0x02)
)
