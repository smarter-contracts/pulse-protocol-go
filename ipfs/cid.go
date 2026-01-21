package ipfs

import (
	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
)

func GetCid(block []byte) (cid.Cid, error) {
	h, err := multihash.Sum(block, multihash.SHA2_256, -1)
	if err != nil {
		return cid.Undef, err
	}
	return cid.NewCidV1(cid.DagCBOR, h), nil
}
