package ipfs

import (
	"bytes"
	"fmt"

	"github.com/ipld/go-ipld-prime/codec/dagcbor"
	"github.com/ipld/go-ipld-prime/node/basicnode"
	"github.com/smarter-contracts/pulse-protocol-go/types/payloads/feedrevocation"
)

// MarshalFeedRevocation encodes a FeedRevocationPayload as a DAG-CBOR map with 8 fields:
// {"t":"feed-revocation","v":1,"en":<bytes>,"iat":<int>,"nk1":<bytes>,"nk2":<bytes>,
//  "rid":<string>,"gcid":<string>}
// (Keys appear in DAG-CBOR canonical order: length ascending, then lexicographic.)
func MarshalFeedRevocation(p *feedrevocation.FeedRevocationPayload) ([]byte, error) {
	nb := basicnode.Prototype.Map.NewBuilder()
	ma, err := nb.BeginMap(8)
	if err != nil {
		return nil, err
	}
	_ = ma.AssembleKey().AssignString("t")
	_ = ma.AssembleValue().AssignString(feedrevocation.Type)
	_ = ma.AssembleKey().AssignString("v")
	_ = ma.AssembleValue().AssignInt(1)
	_ = ma.AssembleKey().AssignString("en")
	_ = ma.AssembleValue().AssignBytes(p.EncryptedNotary)
	_ = ma.AssembleKey().AssignString("iat")
	_ = ma.AssembleValue().AssignInt(p.IssuedAt)
	_ = ma.AssembleKey().AssignString("nk1")
	_ = ma.AssembleValue().AssignBytes(p.NotaryKey1)
	_ = ma.AssembleKey().AssignString("nk2")
	_ = ma.AssembleValue().AssignBytes(p.NotaryKey2)
	_ = ma.AssembleKey().AssignString("rid")
	_ = ma.AssembleValue().AssignString(p.RevokerId)
	_ = ma.AssembleKey().AssignString("gcid")
	_ = ma.AssembleValue().AssignString(p.GrantCID)
	if err := ma.Finish(); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := dagcbor.Encode(nb.Build(), &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnmarshalFeedRevocation decodes a DAG-CBOR block into a FeedRevocationPayload.
func UnmarshalFeedRevocation(block []byte) (*feedrevocation.FeedRevocationPayload, error) {
	na := basicnode.Prototype.Any.NewBuilder()
	if err := dagcbor.Decode(na, bytes.NewReader(block)); err != nil {
		return nil, fmt.Errorf("decoding block to IPLD node: %w", err)
	}
	node := na.Build()

	ty, err := MustString(node, "t")
	if err != nil {
		return nil, fmt.Errorf("t: %w", err)
	}
	if ty != feedrevocation.Type {
		return nil, fmt.Errorf("unexpected structure type: %q", ty)
	}
	ver, err := MustInt(node, "v")
	if err != nil {
		return nil, fmt.Errorf("v: %w", err)
	}
	if ver != 1 {
		return nil, fmt.Errorf("unexpected feed-revocation version: %d", ver)
	}
	en, err := MustBytes(node, "en")
	if err != nil {
		return nil, fmt.Errorf("en: %w", err)
	}
	iat, err := MustInt(node, "iat")
	if err != nil {
		return nil, fmt.Errorf("iat: %w", err)
	}
	nk1, err := MustBytes(node, "nk1")
	if err != nil {
		return nil, fmt.Errorf("nk1: %w", err)
	}
	nk2, err := MustBytes(node, "nk2")
	if err != nil {
		return nil, fmt.Errorf("nk2: %w", err)
	}
	rid, err := MustString(node, "rid")
	if err != nil {
		return nil, fmt.Errorf("rid: %w", err)
	}
	gcid, err := MustString(node, "gcid")
	if err != nil {
		return nil, fmt.Errorf("gcid: %w", err)
	}
	return &feedrevocation.FeedRevocationPayload{
		GrantCID:        gcid,
		RevokerId:       rid,
		IssuedAt:        iat,
		EncryptedNotary: en,
		NotaryKey1:      nk1,
		NotaryKey2:      nk2,
	}, nil
}
