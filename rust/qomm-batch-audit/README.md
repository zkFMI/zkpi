# Public state-continuity batch proofs

The [verification receipt](verification/P5_PUBLIC_CONTINUITY_2026-09-06.json)
records the remote component gate, real in-process DeFMI receipt test, source
hashes, and remaining release and operator gates. Timing is smoke evidence only.

This adapter generates and verifies an actual STARK for a fixed eight-slot batch
of public DeFMI state transitions. It runs outside the online settlement path.
The expected statement must come from the verifier's independently obtained
finalized records. A prover-supplied statement does not establish finality.

The fixed Miden program checks that every entry starts at the previous entry's
state root, that the settlement flag is true, and that the final root and ordered
batch commitment match the public input. The commitment binds both securities
and cash roots, receipt and zkPI digests, entry position, network, deployment,
period, partition, and number of real entries. Unused slots are canonical
unchanged-state entries; an empty period still produces a real complete proof.

## Coverage

| Property | This STARK |
| --- | --- |
| Public root continuity and ordered record binding | Proved |
| All represented settlement flags are true | Proved |
| Receipt authenticity, committee authorization, and chain finality | Supplied by the external finalized-record verifier |
| Hidden input ranges, price policy, winner selection | Not reproved |
| Hidden inventory, guarantee limits, and value conservation | Not reproved |
| Curve commitments, anonymous credentials, and nullifier relations | Not replaced |

This is the P5 public continuity slice, not a claim that the complete current ZK
relations have become post-quantum. Inputs are public records or hashes of public
records; the adapter makes no private-witness privacy claim. Receipt signatures
remain a separate authorization layer. No signed/Merkle checkpoint is called a
STARK, and partial/deferred Miden proofs cannot pass this adapter's verifier.

## Backend and provenance

The maintained backend is [Miden VM](https://github.com/0xMiden/miden-vm), pinned
to the published `miden-vm = 0.32.0` and `miden-core = 0.32.0` crates. The VM crate
archive SHA-256 is
`1e46e30617133c18e4c627f5e022bccae2bc4dd163d5d9cd591d27b5eb06583a`;
its `.cargo_vcs_info.json` records source commit
`12884a0ff13cf5e5de698411b4dad73b35a51e9b`. The registry checksum was checked
against the downloaded official archive. Cargo.lock records transitive versions
and archive checksums. Miden is MIT OR Apache-2.0 licensed. No prover core is
copied or reimplemented here; `batch.masm` is the project-specific relation.

The backend's upstream README identifies it as unaudited alpha software and
unsuitable for production use. The STARK uses Blake3-256 for the proof and Miden
Poseidon2 for its program and record commitments. This prototype does not claim
NIST certification, a quantified quantum security level, or audit approval.

## Shared crypto boundary

`PublicBatchVerifier` implements `zkfmi_crypto::traits::ProofVerifier` for the
closed `MidenPublicBatchV1` suite (wire ID `0x301`, version 1). Offline consumers
explicitly register it with `Provider::register_proof_verifier`. The byte API
accepts the independently derived `BatchStatement` and `BatchProof` as separate
JSON inputs. An ordinary crypto provider rejects this suite until registration;
`zkfmi-crypto` has no dependency on Miden and does not add proving to online paths.

## Commands

Run build and verification only through the repository's remote test harness.
The resulting remote binary accepts:

```text
qomm-batch-audit prove finalized-records.json audit-artifact.json
qomm-batch-audit verify independently-exported-records.json audit-artifact.json
```

The records JSON contains `context`, `initial`, and `transitions` matching the
public Rust types. The proof command refuses to overwrite an existing artifact.
The verify command reconstructs the expected statement from the independent
record file and rejects a mismatching embedded statement. It does not fetch or
authenticate a ledger automatically.

A production scheduler must choose periods independently of requests, invoke
empty-period proving, retain the last trusted finalized root, and publish proof
failures on that same schedule. A fixed-size program alone does not establish
fixed-time publication or traffic-analysis resistance. Actual finality-source
integration and operator scheduling require separate end-to-end evidence.
