package types

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/ipld/go-ipld-prime/codec/dagcbor"
	"github.com/ipld/go-ipld-prime/node/basicnode"
	"github.com/smarter-contracts/pulse-protocol-go/ipfs"
)

// PulseConsentRequestPQ is the wire format for a consent record encrypted with
// ML-KEM-768 (post-quantum hybrid encryption).
// It wraps the encrypted consent data and carries one or more signatures over the
// CID of that data.  The signing scheme is identical to the EC variant — secp256k1
// EIP-191 — only the encryption layer differs.
//
// CBOR: {"t":"consent-pq","v":1,"ed":<bytes>,"sigs":[<bytes>,...]}
// where "ed" is the DAG-CBOR encoding of the inner PulsePQEncryptionResult.
type PulseConsentRequestPQ struct {
	EncryptedData PulsePQEncryptionResult `json:"consent"`
	Signatures    [][]byte                `json:"signatures"`
}

// PulseRevokeRequestPQ is the wire format for a revoke record encrypted with
// ML-KEM-768 (post-quantum hybrid encryption).
// It carries the CID of the original consent being revoked, the encrypted revoke
// payload, and a single signature from one of the original consent signers.
//
// CBOR: {"t":"revoke-pq","v":1,"ccid":<string>,"ed":<bytes>,"sig":<bytes>}
// where "ed" is the DAG-CBOR encoding of the inner PulsePQEncryptionResult.
type PulseRevokeRequestPQ struct {
	ConsentCid    string                  `json:"consentCid"`
	EncryptedData PulsePQEncryptionResult `json:"revoke"`
	Signature     []byte                  `json:"signature"`
}

// ── PulseConsentRequestPQ — SignableConsent ───────────────────────────────────

func (p *PulseConsentRequestPQ) EncryptedDataCBOR() ([]byte, error) {
	return p.EncryptedData.MarshalCBOR()
}

func (p *PulseConsentRequestPQ) AppendSignature(sig []byte) {
	p.Signatures = append(p.Signatures, sig)
}

// ── PulseConsentRequestPQ — JSON ──────────────────────────────────────────────

func (p *PulseConsentRequestPQ) MarshalJSON() ([]byte, error) {
	type Alias PulseConsentRequestPQ
	return json.Marshal((*Alias)(p))
}

func (p *PulseConsentRequestPQ) UnmarshalJSON(data []byte) error {
	type Alias PulseConsentRequestPQ
	return json.Unmarshal(data, (*Alias)(p))
}

// ── PulseConsentRequestPQ — DAG-CBOR ──────────────────────────────────────────

func (p *PulseConsentRequestPQ) MarshalCBOR() ([]byte, error) {
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
	_ = ma.AssembleValue().AssignString("consent-pq")

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

func (p *PulseConsentRequestPQ) UnmarshalCBOR(block []byte) error {
	na := basicnode.Prototype.Any.NewBuilder()
	if err := dagcbor.Decode(na, bytes.NewReader(block)); err != nil {
		return fmt.Errorf("decoding CBOR: %w", err)
	}
	node := na.Build()

	ty, err := ipfs.MustString(node, "t")
	if err != nil {
		return fmt.Errorf("t: %w", err)
	}
	if ty != "consent-pq" {
		return fmt.Errorf("unexpected structure type: %q", ty)
	}

	ver, err := ipfs.MustInt(node, "v")
	if err != nil {
		return fmt.Errorf("v: %w", err)
	}
	if ver != 1 {
		return fmt.Errorf("unexpected consent-pq version: %d", ver)
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

// ── PulseRevokeRequestPQ — SignableRevoke ─────────────────────────────────────

func (p *PulseRevokeRequestPQ) EncryptedDataCBOR() ([]byte, error) {
	return p.EncryptedData.MarshalCBOR()
}

func (p *PulseRevokeRequestPQ) GetConsentCid() string {
	return p.ConsentCid
}

func (p *PulseRevokeRequestPQ) AppendSignature(sig []byte) {
	p.Signature = sig
}

// ── PulseRevokeRequestPQ — JSON ───────────────────────────────────────────────

func (p *PulseRevokeRequestPQ) MarshalJSON() ([]byte, error) {
	type Alias PulseRevokeRequestPQ
	return json.Marshal((*Alias)(p))
}

func (p *PulseRevokeRequestPQ) UnmarshalJSON(data []byte) error {
	type Alias PulseRevokeRequestPQ
	return json.Unmarshal(data, (*Alias)(p))
}

// ── PulseRevokeRequestPQ — DAG-CBOR ───────────────────────────────────────────

func (p *PulseRevokeRequestPQ) MarshalCBOR() ([]byte, error) {
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
	_ = ma.AssembleValue().AssignString("revoke-pq")

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

func (p *PulseRevokeRequestPQ) UnmarshalCBOR(block []byte) error {
	na := basicnode.Prototype.Any.NewBuilder()
	if err := dagcbor.Decode(na, bytes.NewReader(block)); err != nil {
		return fmt.Errorf("decoding CBOR: %w", err)
	}
	node := na.Build()

	ty, err := ipfs.MustString(node, "t")
	if err != nil {
		return fmt.Errorf("t: %w", err)
	}
	if ty != "revoke-pq" {
		return fmt.Errorf("unexpected structure type: %q", ty)
	}

	ver, err := ipfs.MustInt(node, "v")
	if err != nil {
		return fmt.Errorf("v: %w", err)
	}
	if ver != 1 {
		return fmt.Errorf("unexpected revoke-pq version: %d", ver)
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
