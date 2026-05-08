package ipfs

import (
	"bytes"
	"fmt"

	ipld "github.com/ipld/go-ipld-prime"
	"github.com/ipld/go-ipld-prime/codec/dagcbor"
	"github.com/ipld/go-ipld-prime/node/basicnode"
	"github.com/smarter-contracts/pulse-protocol-go/types/payloads/feedpermission"
)

// MarshalFeedPermission encodes a FeedPermissionPayload as a DAG-CBOR map with 15 fields:
// {"t":"feed-permission","v":1,"cn":<int>,"dc":[...],"en":<bytes>,"ft":<string>,
//  "pm":[...],"cpd":<string>,"exp":<int>,"iat":<int>,"nk1":<bytes>,"nk2":<bytes>,
//  "pcp":<string>,"wid":<string>,"gwid":<string>}
// (Keys appear in DAG-CBOR canonical order: length ascending, then lexicographic.)
func MarshalFeedPermission(p *feedpermission.FeedPermissionPayload) ([]byte, error) {
	nb := basicnode.Prototype.Map.NewBuilder()
	ma, err := nb.BeginMap(15)
	if err != nil {
		return nil, err
	}
	_ = ma.AssembleKey().AssignString("t")
	_ = ma.AssembleValue().AssignString(feedpermission.Type)
	_ = ma.AssembleKey().AssignString("v")
	_ = ma.AssembleValue().AssignInt(1)
	_ = ma.AssembleKey().AssignString("cn")
	_ = ma.AssembleValue().AssignInt(int64(p.ConsentNo))
	_ = ma.AssembleKey().AssignString("dc")
	if err := encodeStringSlice(ma.AssembleValue(), p.DataCategories); err != nil {
		return nil, fmt.Errorf("dc: %w", err)
	}
	_ = ma.AssembleKey().AssignString("en")
	_ = ma.AssembleValue().AssignBytes(p.EncryptedNotary)
	_ = ma.AssembleKey().AssignString("ft")
	_ = ma.AssembleValue().AssignString(p.FeedType)
	_ = ma.AssembleKey().AssignString("pm")
	if err := encodeStringSlice(ma.AssembleValue(), p.Permissions); err != nil {
		return nil, fmt.Errorf("pm: %w", err)
	}
	_ = ma.AssembleKey().AssignString("cpd")
	_ = ma.AssembleValue().AssignString(p.CounterpartyDid)
	_ = ma.AssembleKey().AssignString("exp")
	_ = ma.AssembleValue().AssignInt(p.ExpiresAt)
	_ = ma.AssembleKey().AssignString("iat")
	_ = ma.AssembleValue().AssignInt(p.IssuedAt)
	_ = ma.AssembleKey().AssignString("nk1")
	_ = ma.AssembleValue().AssignBytes(p.NotaryKey1)
	_ = ma.AssembleKey().AssignString("nk2")
	_ = ma.AssembleValue().AssignBytes(p.NotaryKey2)
	_ = ma.AssembleKey().AssignString("pcp")
	_ = ma.AssembleValue().AssignString(p.PodContainerPath)
	_ = ma.AssembleKey().AssignString("wid")
	_ = ma.AssembleValue().AssignString(p.WalletId)
	_ = ma.AssembleKey().AssignString("gwid")
	_ = ma.AssembleValue().AssignString(p.GrantorWebId)
	if err := ma.Finish(); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := dagcbor.Encode(nb.Build(), &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnmarshalFeedPermission decodes a DAG-CBOR block into a FeedPermissionPayload.
func UnmarshalFeedPermission(block []byte) (*feedpermission.FeedPermissionPayload, error) {
	na := basicnode.Prototype.Any.NewBuilder()
	if err := dagcbor.Decode(na, bytes.NewReader(block)); err != nil {
		return nil, fmt.Errorf("decoding block to IPLD node: %w", err)
	}
	node := na.Build()

	ty, err := MustString(node, "t")
	if err != nil {
		return nil, fmt.Errorf("t: %w", err)
	}
	if ty != feedpermission.Type {
		return nil, fmt.Errorf("unexpected structure type: %q", ty)
	}
	ver, err := MustInt(node, "v")
	if err != nil {
		return nil, fmt.Errorf("v: %w", err)
	}
	if ver != 1 {
		return nil, fmt.Errorf("unexpected feed-permission version: %d", ver)
	}
	cn, err := MustInt(node, "cn")
	if err != nil {
		return nil, fmt.Errorf("cn: %w", err)
	}
	wid, err := MustString(node, "wid")
	if err != nil {
		return nil, fmt.Errorf("wid: %w", err)
	}
	gwid, err := MustString(node, "gwid")
	if err != nil {
		return nil, fmt.Errorf("gwid: %w", err)
	}
	cpd, err := MustString(node, "cpd")
	if err != nil {
		return nil, fmt.Errorf("cpd: %w", err)
	}
	ft, err := MustString(node, "ft")
	if err != nil {
		return nil, fmt.Errorf("ft: %w", err)
	}
	pcp, err := MustString(node, "pcp")
	if err != nil {
		return nil, fmt.Errorf("pcp: %w", err)
	}
	pm, err := MustStringList(node, "pm")
	if err != nil {
		return nil, fmt.Errorf("pm: %w", err)
	}
	dc, err := MustStringList(node, "dc")
	if err != nil {
		return nil, fmt.Errorf("dc: %w", err)
	}
	iat, err := MustInt(node, "iat")
	if err != nil {
		return nil, fmt.Errorf("iat: %w", err)
	}
	exp, err := MustInt(node, "exp")
	if err != nil {
		return nil, fmt.Errorf("exp: %w", err)
	}
	en, err := MustBytes(node, "en")
	if err != nil {
		return nil, fmt.Errorf("en: %w", err)
	}
	nk1, err := MustBytes(node, "nk1")
	if err != nil {
		return nil, fmt.Errorf("nk1: %w", err)
	}
	nk2, err := MustBytes(node, "nk2")
	if err != nil {
		return nil, fmt.Errorf("nk2: %w", err)
	}
	return &feedpermission.FeedPermissionPayload{
		ConsentNo:        uint32(cn),
		WalletId:         wid,
		GrantorWebId:     gwid,
		CounterpartyDid:  cpd,
		FeedType:         ft,
		PodContainerPath: pcp,
		Permissions:      pm,
		DataCategories:   dc,
		IssuedAt:         iat,
		ExpiresAt:        exp,
		EncryptedNotary:  en,
		NotaryKey1:       nk1,
		NotaryKey2:       nk2,
	}, nil
}

// encodeStringSlice writes a string slice into an IPLD list via na.
func encodeStringSlice(na ipld.NodeAssembler, ss []string) error {
	la, err := na.BeginList(int64(len(ss)))
	if err != nil {
		return err
	}
	for _, s := range ss {
		if err := la.AssembleValue().AssignString(s); err != nil {
			return err
		}
	}
	return la.Finish()
}
