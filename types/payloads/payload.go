// Package payloads defines the unencrypted consent payload types used across
// the Pulse Protocol ecosystem.
//
// All consent payloads embed ConsentPayloadHeader, which provides the Type and
// Version discriminator fields. Any party that can decrypt a consent record can
// read the header to determine how to deserialise the remaining fields.
//
// The mid-tier and protocol layer never inspect these types directly — the
// payload is encrypted before submission and treated as opaque bytes throughout
// the storage and anchoring pipeline.
package payloads

// ConsentPayloadHeader is the common discriminator embedded at the top of every
// consent payload. It allows any party that can decrypt a consent to determine
// the payload type and version before attempting to deserialise the full record.
type ConsentPayloadHeader struct {
	Type    string `json:"type"    cbor:"t"`
	Version string `json:"version" cbor:"v"`
}
