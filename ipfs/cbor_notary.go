package ipfs

import (
	"bytes"
	"fmt"
	"time"

	"github.com/ipld/go-ipld-prime/codec/dagcbor"
	"github.com/ipld/go-ipld-prime/node/basicnode"
	pptypes "github.com/smarter-contracts/pulse-protocol-go/types"
)

// MarshalNotaryBlock encodes a NotaryBlock as a DAG-CBOR map:
// {"t":"notary","v":1,"ts":<int64 Unix secs>,"ip":<string>,"ua":<string>,"loc":<string>}
func MarshalNotaryBlock(n *pptypes.NotaryBlock) ([]byte, error) {
	nb := basicnode.Prototype.Map.NewBuilder()
	ma, err := nb.BeginMap(6)
	if err != nil {
		return nil, err
	}
	_ = ma.AssembleKey().AssignString("t")
	_ = ma.AssembleValue().AssignString("notary")
	_ = ma.AssembleKey().AssignString("v")
	_ = ma.AssembleValue().AssignInt(1)
	_ = ma.AssembleKey().AssignString("ts")
	_ = ma.AssembleValue().AssignInt(n.Timestamp.Unix())
	_ = ma.AssembleKey().AssignString("ip")
	_ = ma.AssembleValue().AssignString(n.IPAddress)
	_ = ma.AssembleKey().AssignString("ua")
	_ = ma.AssembleValue().AssignString(n.UserAgent)
	_ = ma.AssembleKey().AssignString("loc")
	_ = ma.AssembleValue().AssignString(n.Location)
	if err := ma.Finish(); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := dagcbor.Encode(nb.Build(), &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnmarshalNotaryBlock decodes a DAG-CBOR block into a NotaryBlock.
func UnmarshalNotaryBlock(block []byte) (*pptypes.NotaryBlock, error) {
	na := basicnode.Prototype.Any.NewBuilder()
	if err := dagcbor.Decode(na, bytes.NewReader(block)); err != nil {
		return nil, fmt.Errorf("decoding block to IPLD node: %w", err)
	}
	node := na.Build()

	ty, err := MustString(node, "t")
	if err != nil {
		return nil, fmt.Errorf("t: %w", err)
	}
	if ty != "notary" {
		return nil, fmt.Errorf("unexpected structure type: %q", ty)
	}
	ver, err := MustInt(node, "v")
	if err != nil {
		return nil, fmt.Errorf("v: %w", err)
	}
	if ver != 1 {
		return nil, fmt.Errorf("unexpected notary version: %d", ver)
	}
	ts, err := MustInt(node, "ts")
	if err != nil {
		return nil, fmt.Errorf("ts: %w", err)
	}
	ip, err := MustString(node, "ip")
	if err != nil {
		return nil, fmt.Errorf("ip: %w", err)
	}
	ua, err := MustString(node, "ua")
	if err != nil {
		return nil, fmt.Errorf("ua: %w", err)
	}
	loc, err := MustString(node, "loc")
	if err != nil {
		return nil, fmt.Errorf("loc: %w", err)
	}
	return &pptypes.NotaryBlock{
		Timestamp: time.Unix(ts, 0).UTC(),
		IPAddress: ip,
		UserAgent: ua,
		Location:  loc,
	}, nil
}
