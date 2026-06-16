# pulse-protocol-go

A Go workspace containing the core cryptographic and protocol libraries for the Pulse Permissions Protocol. These libraries provide the building blocks for consent lifecycle management: HD wallet derivation, EC and post-quantum encryption, DAG-CBOR serialisation, IPFS CIDv1 computation, and a consent engine that wires them together.

## Modules

| Module | Import path | Purpose |
|---|---|---|
| `types` | `github.com/smarter-contracts/pulse-protocol-go/types/v2` | Wire-format types: encryption results, request bodies, payload structs, storage interfaces |
| `ipfs` | `github.com/smarter-contracts/pulse-protocol-go/ipfs/v2` | DAG-CBOR serialisation of consent/revoke records and CIDv1 computation |
| `crypto` | `github.com/smarter-contracts/pulse-protocol-go/crypto/v2` | HD wallet derivation, ECDH encryption, ML-KEM-768 (post-quantum), EIP-191 signing |
| `consent` | `github.com/smarter-contracts/pulse-protocol-go/consent` | Consent engine: ingest, review, approve/reject, revoke, sync, xpub exchange |
| `registry` | `github.com/smarter-contracts/pulse-protocol-go/registry` | `OtherPartyRegistry` interface and in-memory reference implementation |

## Dependency flow

```
types/v2 ──────────────────────────────────────┐
                                                ▼
types/v2 ──► ipfs/v2 ──► crypto/v2 ──────────► consent
                                    └──────────► registry (interface only)
```

`consent` depends on `crypto/v2`, `ipfs/v2`, and `types/v2`. The `types` and `ipfs` modules have no dependency on `crypto`. `registry` is a standalone interface with no inter-module dependencies.

## Development

This is a [Go workspace](https://go.dev/ref/mod#workspaces). All modules are listed in `go.work` so changes in one module are immediately visible to others without publishing a tag.

```bash
# Run all tests across every module
go test ./...

# Run tests for one module
cd crypto && go test ./...
```

Each module has its own `go.mod` and version history. See the individual READMEs and `CHANGELOG.md` files for details.

## Version tagging convention

Modules are tagged individually using the `<module>/<version>` prefix format (e.g. `types/v2.0.0`, `crypto/v2.0.1`). Major versions ≥ 2 use the `/v2` import path suffix required by Go modules.

| Module | Current version | Import path suffix |
|---|---|---|
| `types` | `v2.0.0` | `/v2` |
| `ipfs` | `v2.0.0` | `/v2` |
| `crypto` | `v2.0.1` | `/v2` |
| `consent` | `v0.2.0` | none (pre-1.0) |
| `registry` | `v1.0.0` | none |

## TypeScript counterpart

[`pulse-protocol-ts`](https://github.com/smarter-contracts/pulse-protocol-ts) is a byte-identical TypeScript implementation of the same protocol covering `crypto`, `ipfs`, and `types`. Both implementations produce the same DAG-CBOR bytes and IPFS CIDs for the same inputs.
