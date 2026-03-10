package types

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/ipld/go-ipld-prime/codec/dagcbor"
	"github.com/ipld/go-ipld-prime/node/basicnode"
	"github.com/smarter-contracts/pulse-protocol-go/ipfs"
)

// PulseConsentRequestEC is the wire format for a consent record encrypted with EC (ECDH).
// It wraps the encrypted consent data and carries one or more signatures over the CID of
// that data.  The first signature is from the initiating party; the second (if present)
// is from the counterparty after they have verified and counter-signed.
//
// CBOR: {"t":"consent-ec","v":1,"ed":<bytes>,"sigs":[<bytes>,...]}
// where "ed" is the DAG-CBOR encoding of the inner PulseECEncryptionResult.
type PulseConsentRequestEC struct {
	EncryptedData PulseECEncryptionResult `json:"consent"`
	Signatures    [][]byte                `json:"signatures"`
}

// PulseRevokeRequestEC is the wire format for a revoke record encrypted with EC (ECDH).
// It carries the CID of the original consent being revoked, the encrypted revoke payload,
// and a single signature (which must come from one of the original consent signers).
//
// CBOR: {"t":"revoke-ec","v":1,"ccid":<string>,"ed":<bytes>,"sig":<bytes>}
// where "ed" is the DAG-CBOR encoding of the inner PulseECEncryptionResult.
type PulseRevokeRequestEC struct {
	ConsentCid    string                  `json:"consentCid"`
	EncryptedData PulseECEncryptionResult `json:"revoke"`
	Signature     []byte                  `json:"signature"`
}

// ── PulseConsentRequestEC — SignableConsent ───────────────────────────────────────────

func (p *PulseConsentRequestEC) EncryptedDataCBOR() ([]byte, error) {
	return p.EncryptedData.MarshalCBOR()
}

func (p *PulseConsentRequestEC) AppendSignature(sig []byte) {
	p.Signatures = append(p.Signatures, sig)
}

// ── PulseConsentRequestEC — JSON ─────────────────────────────────────────────────────

func (p *PulseConsentRequestEC) MarshalJSON() ([]byte, error) {
	type Alias PulseConsentRequestEC
	return json.Marshal((*Alias)(p))
}

func (p *PulseConsentRequestEC) UnmarshalJSON(data []byte) error {
	type Alias PulseConsentRequestEC
	return json.Unmarshal(data, (*Alias)(p))
}

// ── PulseConsentRequestEC — DAG-CBOR ─────────────────────────────────────────────────

func (p *PulseConsentRequestEC) MarshalCBOR() ([]byte, error) {
	edBytes, err := p.EncryptedData.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("marshalling encrypted data: %w", err)
	}

	nb := basicnode.Prototype.Map.NewBuilder()
	ma, err := nb.BeginMap(4)
	if err != nil {
		return nil, err
	}

	_ = ma.AssembleKey().AssignString("t")
	_ = ma.AssembleValue().AssignString("consent-ec")

	_ = ma.AssembleKey().AssignString("v")
	_ = ma.AssembleValue().AssignInt(1)

	_ = ma.AssembleKey().AssignString("ed")
	_ = ma.AssembleValue().AssignBytes(edBytes)

	_ = ma.AssembleKey().AssignString("sigs")
	la, err := ma.AssembleValue().BeginList(int64(len(p.Signatures)))
	if err != nil {
		return nil, err
	}
	for _, sig := range p.Signatures {
		if err := la.AssembleValue().AssignBytes(sig); err != nil {
			return nil, err
		}
	}
	if err := la.Finish(); err != nil {
		return nil, err
	}

	if err := ma.Finish(); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := dagcbor.Encode(nb.Build(), &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (p *PulseConsentRequestEC) UnmarshalCBOR(block []byte) error {
	na := basicnode.Prototype.Any.NewBuilder()
	if err := dagcbor.Decode(na, bytes.NewReader(block)); err != nil {
		return fmt.Errorf("decoding CBOR: %w", err)
	}
	node := na.Build()

	ty, err := ipfs.MustString(node, "t")
	if err != nil {
		return fmt.Errorf("t: %w", err)
	}
	if ty != "consent-ec" {
		return fmt.Errorf("unexpected structure type: %q", ty)
	}

	ver, err := ipfs.MustInt(node, "v")
	if err != nil {
		return fmt.Errorf("v: %w", err)
	}
	if ver != 1 {
		return fmt.Errorf("unexpected consent-ec version: %d", ver)
	}

	edBytes, err := ipfs.MustBytes(node, "ed")
	if err != nil {
		return fmt.Errorf("ed: %w", err)
	}
	if err := p.EncryptedData.UnmarshalCBOR(edBytes); err != nil {
		return fmt.Errorf("decoding encrypted data: %w", err)
	}

	sigsNode, err := node.LookupByString("sigs")
	if err != nil {
		return fmt.Errorf("sigs: %w", err)
	}
	it := sigsNode.ListIterator()
	var sigs [][]byte
	for !it.Done() {
		_, sn, err := it.Next()
		if err != nil {
			return err
		}
		sig, err := sn.AsBytes()
		if err != nil {
			return fmt.Errorf("signature element: %w", err)
		}
		sigs = append(sigs, sig)
	}
	p.Signatures = sigs

	return nil
}

// ── PulseRevokeRequestEC — SignableRevoke ─────────────────────────────────────────────

func (p *PulseRevokeRequestEC) EncryptedDataCBOR() ([]byte, error) {
	return p.EncryptedData.MarshalCBOR()
}

func (p *PulseRevokeRequestEC) GetConsentCid() string {
	return p.ConsentCid
}

func (p *PulseRevokeRequestEC) AppendSignature(sig []byte) {
	p.Signature = sig
}

// ── PulseRevokeRequestEC — JSON ───────────────────────────────────────────────────────

func (p *PulseRevokeRequestEC) MarshalJSON() ([]byte, error) {
	type Alias PulseRevokeRequestEC
	return json.Marshal((*Alias)(p))
}

func (p *PulseRevokeRequestEC) UnmarshalJSON(data []byte) error {
	type Alias PulseRevokeRequestEC
	return json.Unmarshal(data, (*Alias)(p))
}

// ── PulseRevokeRequestEC — DAG-CBOR ───────────────────────────────────────────────────

func (p *PulseRevokeRequestEC) MarshalCBOR() ([]byte, error) {
	edBytes, err := p.EncryptedData.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("marshalling encrypted data: %w", err)
	}

	nb := basicnode.Prototype.Map.NewBuilder()
	ma, err := nb.BeginMap(5)
	if err != nil {
		return nil, err
	}

	_ = ma.AssembleKey().AssignString("t")
	_ = ma.AssembleValue().AssignString("revoke-ec")

	_ = ma.AssembleKey().AssignString("v")
	_ = ma.AssembleValue().AssignInt(1)

	_ = ma.AssembleKey().AssignString("ccid")
	_ = ma.AssembleValue().AssignString(p.ConsentCid)

	_ = ma.AssembleKey().AssignString("ed")
	_ = ma.AssembleValue().AssignBytes(edBytes)

	_ = ma.AssembleKey().AssignString("sig")
	_ = ma.AssembleValue().AssignBytes(p.Signature)

	if err := ma.Finish(); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := dagcbor.Encode(nb.Build(), &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (p *PulseRevokeRequestEC) UnmarshalCBOR(block []byte) error {
	na := basicnode.Prototype.Any.NewBuilder()
	if err := dagcbor.Decode(na, bytes.NewReader(block)); err != nil {
		return fmt.Errorf("decoding CBOR: %w", err)
	}
	node := na.Build()

	ty, err := ipfs.MustString(node, "t")
	if err != nil {
		return fmt.Errorf("t: %w", err)
	}
	if ty != "revoke-ec" {
		return fmt.Errorf("unexpected structure type: %q", ty)
	}

	ver, err := ipfs.MustInt(node, "v")
	if err != nil {
		return fmt.Errorf("v: %w", err)
	}
	if ver != 1 {
		return fmt.Errorf("unexpected revoke-ec version: %d", ver)
	}

	ccid, err := ipfs.MustString(node, "ccid")
	if err != nil {
		return fmt.Errorf("ccid: %w", err)
	}
	p.ConsentCid = ccid

	edBytes, err := ipfs.MustBytes(node, "ed")
	if err != nil {
		return fmt.Errorf("ed: %w", err)
	}
	if err := p.EncryptedData.UnmarshalCBOR(edBytes); err != nil {
		return fmt.Errorf("decoding encrypted data: %w", err)
	}

	sig, err := ipfs.MustBytes(node, "sig")
	if err != nil {
		return fmt.Errorf("sig: %w", err)
	}
	p.Signature = sig

	return nil
}
