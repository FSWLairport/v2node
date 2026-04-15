package dynamicguard

import "errors"

var (
	errInvalidPacketSize  = errors.New("invalid packet size")
	errInvalidMagic       = errors.New("invalid magic")
	errUnsupportedVersion = errors.New("unsupported version")
	errInvalidCookieLen   = errors.New("invalid cookie length")
	errInvalidPowNonceLen = errors.New("invalid pow_nonce length")
	errUserKeyNotFound    = errors.New("user_key not found")
	errMACVerifyFailed    = errors.New("MAC verification failed")
	errDeviceRevoked      = errors.New("device revoked")
	errDevicePubMismatch  = errors.New("device wg_static_pub mismatch")
	errDeviceLimitReached = errors.New("device limit reached")
	errIPPoolExhausted    = errors.New("IP pool exhausted")
	errIPPoolNotFound     = errors.New("IP pool not found for group")
	errCookieInvalid      = errors.New("cookie invalid")
	errPoWInvalid         = errors.New("PoW invalid")
)
