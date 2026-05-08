// Package ipfs provides IPFS content-addressing utilities for the Pulse
// Protocol, including DAG-CBOR CID computation and IPLD node field accessors.
package ipfs

import (
	"fmt"

	"github.com/ipld/go-ipld-prime"
)

// MustBytes looks up key in the IPLD node n and returns the value as a byte slice.
func MustBytes(n ipld.Node, key string) ([]byte, error) {
	v, err := n.LookupByString(key)
	if err != nil {
		return nil, err
	}
	return v.AsBytes()
}

// MustString looks up key in the IPLD node n and returns the value as a string.
func MustString(n ipld.Node, key string) (string, error) {
	v, err := n.LookupByString(key)
	if err != nil {
		return "", err
	}
	return v.AsString()
}

// MustInt looks up key in the IPLD node n and returns the value as an int64.
func MustInt(n ipld.Node, key string) (int64, error) {
	v, err := n.LookupByString(key)
	if err != nil {
		return 0, err
	}
	return v.AsInt()
}

// MustStringList looks up key in the IPLD node n and returns the value as a
// slice of strings. The node value must be a list of string elements.
func MustStringList(n ipld.Node, key string) ([]string, error) {
	v, err := n.LookupByString(key)
	if err != nil {
		return nil, err
	}
	it := v.ListIterator()
	if it == nil {
		return nil, fmt.Errorf("%q is not a list", key)
	}
	var out []string
	for !it.Done() {
		_, elem, err := it.Next()
		if err != nil {
			return nil, err
		}
		s, err := elem.AsString()
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}
