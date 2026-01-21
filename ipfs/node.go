package ipfs

import (
	"github.com/ipld/go-ipld-prime"
)

func MustBytes(n ipld.Node, key string) ([]byte, error) {
	v, err := n.LookupByString(key)
	if err != nil {
		return nil, err
	}
	return v.AsBytes()
}

func MustString(n ipld.Node, key string) (string, error) {
	v, err := n.LookupByString(key)
	if err != nil {
		return "", err
	}
	return v.AsString()
}

func MustInt(n ipld.Node, key string) (int64, error) {
	v, err := n.LookupByString(key)
	if err != nil {
		return 0, err
	}
	return v.AsInt()
}
