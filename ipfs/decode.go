package ipfs

import (
	"fmt"

	pptypes "github.com/smarter-contracts/pulse-protocol-go/types"
	v1 "github.com/smarter-contracts/pulse-protocol-go/types/v1"
)

// RecordKind identifies the version and encryption scheme of a decoded block.
type RecordKind uint8

const (
	RecordKindV2EC RecordKind = iota // V2 EC two-party consent/revoke
	RecordKindV2PQ                   // V2 PQ multi-party consent/revoke
	RecordKindV1EC                   // V1 legacy EC consent/revoke
	RecordKindV1PQ                   // V1 legacy PQ consent/revoke
)

// DecodedConsentBlock is the result of decoding a DAG-CBOR consent block.
// Exactly one of the pointer fields is non-nil; Kind identifies which.
type DecodedConsentBlock struct {
	Kind RecordKind
	V2EC *pptypes.ConsentStructure      // non-nil when Kind == RecordKindV2EC
	V2PQ *pptypes.ConsentStructureMulti // non-nil when Kind == RecordKindV2PQ
	V1EC *v1.ConsentStructure           // non-nil when Kind == RecordKindV1EC
	V1PQ *v1.ConsentStructureMulti      // non-nil when Kind == RecordKindV1PQ
}

// DecodedRevokeBlock is the result of decoding a DAG-CBOR revoke block.
// Exactly one of the pointer fields is non-nil; Kind identifies which.
type DecodedRevokeBlock struct {
	Kind RecordKind
	V2EC *pptypes.RevokeStructure      // non-nil when Kind == RecordKindV2EC
	V2PQ *pptypes.RevokeStructureMulti // non-nil when Kind == RecordKindV2PQ
	V1EC *v1.RevokeStructure           // non-nil when Kind == RecordKindV1EC
	V1PQ *v1.RevokeStructureMulti      // non-nil when Kind == RecordKindV1PQ
}

// DecodeConsent decodes raw DAG-CBOR bytes into the appropriate consent
// structure, detecting V2 vs V1 and EC vs PQ automatically.
//
// Detection order: V2-EC → V2-PQ → V1-EC → V1-PQ. V2 records carry a "t"
// discriminator field; V1 records do not.
func DecodeConsent(block []byte) (*DecodedConsentBlock, error) {
	if v2ec, err := UnmarshalConsentEC(block); err == nil {
		return &DecodedConsentBlock{Kind: RecordKindV2EC, V2EC: v2ec}, nil
	}
	if v2pq, err := UnmarshalConsentPQ(block); err == nil {
		return &DecodedConsentBlock{Kind: RecordKindV2PQ, V2PQ: v2pq}, nil
	}
	if v1ec, err := UnmarshalV1ConsentEC(block); err == nil {
		return &DecodedConsentBlock{Kind: RecordKindV1EC, V1EC: v1ec}, nil
	}
	if v1pq, err := UnmarshalV1ConsentPQ(block); err == nil {
		return &DecodedConsentBlock{Kind: RecordKindV1PQ, V1PQ: v1pq}, nil
	}
	return nil, fmt.Errorf("block does not match any known consent structure version")
}

// DecodeRevoke decodes raw DAG-CBOR bytes into the appropriate revoke
// structure, detecting V2 vs V1 and EC vs PQ automatically.
func DecodeRevoke(block []byte) (*DecodedRevokeBlock, error) {
	if v2ec, err := UnmarshalRevokeEC(block); err == nil {
		return &DecodedRevokeBlock{Kind: RecordKindV2EC, V2EC: v2ec}, nil
	}
	if v2pq, err := UnmarshalRevokePQ(block); err == nil {
		return &DecodedRevokeBlock{Kind: RecordKindV2PQ, V2PQ: v2pq}, nil
	}
	if v1ec, err := UnmarshalV1RevokeEC(block); err == nil {
		return &DecodedRevokeBlock{Kind: RecordKindV1EC, V1EC: v1ec}, nil
	}
	if v1pq, err := UnmarshalV1RevokePQ(block); err == nil {
		return &DecodedRevokeBlock{Kind: RecordKindV1PQ, V1PQ: v1pq}, nil
	}
	return nil, fmt.Errorf("block does not match any known revoke structure version")
}

// ComputeCID computes the DAG-CBOR CIDv1 string from pre-marshalled bytes.
// Use the Marshal* functions (e.g. MarshalConsentEC) to obtain the bytes.
func ComputeCID(block []byte) (string, error) {
	c, err := GetCid(block)
	if err != nil {
		return "", fmt.Errorf("computing CID: %w", err)
	}
	return c.String(), nil
}
