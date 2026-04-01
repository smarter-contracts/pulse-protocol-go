// Package types defines the wire-format types for Pulse Protocol encryption
// results and consent/revoke request structures.  Types support JSON serialisation
// and DAG-CBOR encoding via the ipfs package.
package types

// JSONSerializable is implemented by types that can be encoded to and decoded
// from JSON.
type JSONSerializable interface {
	MarshalJSON() ([]byte, error)
	UnmarshalJSON([]byte) error
}
