package types

import "github.com/ipld/go-ipld-prime"

type CBORSerializable interface {
	MarshalCBOR() ([]byte, error)
	UnmarshalCBOR(ipld.Node) error
}

type JSONSerializable interface {
	MarshalJSON() ([]byte, error)
	UnmarshalJSON([]byte) error
}

type Serializable interface {
	CBORSerializable
	JSONSerializable
}
