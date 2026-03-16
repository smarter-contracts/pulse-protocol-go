// Package types defines the wire-format types for Pulse Protocol encryption
// results and consent/revoke request structures.  Types support both DAG-CBOR
// (for content-addressed storage) and JSON serialisation.
package types

// CBORSerializable is implemented by types that can be encoded to and decoded
// from DAG-CBOR.
type CBORSerializable interface {
	MarshalCBOR() ([]byte, error)
	UnmarshalCBOR([]byte) error
}

// JSONSerializable is implemented by types that can be encoded to and decoded
// from JSON.
type JSONSerializable interface {
	MarshalJSON() ([]byte, error)
	UnmarshalJSON([]byte) error
}

// Serializable is implemented by types that support both DAG-CBOR and JSON
// serialisation.
type Serializable interface {
	CBORSerializable
	JSONSerializable
}
