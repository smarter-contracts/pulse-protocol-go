package ipfs

import (
	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
)

// GetCid computes a CIDv1 content identifier for the given DAG-CBOR block
// using the SHA2-256 multihash.
func GetCid(block []byte) (cid.Cid, error) {
	h, err := multihash.Sum(block, multihash.SHA2_256, -1)
	if err != nil {
		return cid.Undef, err
	}
	return cid.NewCidV1(cid.DagCBOR, h), nil
}
