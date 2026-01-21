package types

type CBORSerializable interface {
	MarshalCBOR() ([]byte, error)
	UnmarshalCBOR([]byte) error
}

type JSONSerializable interface {
	MarshalJSON() ([]byte, error)
	UnmarshalJSON([]byte) error
}

type Serializable interface {
	CBORSerializable
	JSONSerializable
}
