# zkpi-optimistic

Optional optimistic assurance for MPC applications. `joint_proof` remains the
default. This crate owns the shared proposal, challenge, deadline and collateral
state machine; it does not perform matching or replace monetary proofs.

## Protocol

1. The consensus host enrolls an application policy with a pinned verifier,
   proposer identity, bond asset, bond amounts and time windows. It debits a real
   collateral account before crediting escrow.
2. The host registers the admitted execution input, including network,
   application, verifier, job, input root and preceding state root. The node
   checks this admission against its executed input and persists its signed
   proposal before returning it. One signature authenticates a provisional
   result; it does not prove correctness.
3. A challenger locks the policy's challenger bond before the challenge
   deadline. Anyone may relay the application's existing proof for precisely
   the registered input. Invalid evidence is rejected without resolving the
   dispute. A valid contradictory result or a missed response deadline rejects
   the claim and transfers the proposer bond to the challenger.
4. A valid matching proof defeats the challenge and transfers the challenger
   bond to the proposer. Even then, settlement waits for the original challenge
   deadline. Unchallenged proposals become final only after that deadline.
5. Settlement checks `require_finalized` against canonical host state and its
   expected execution context and output. A client timer or serialized status
   cannot authorize customer asset movement.

Deadlines use consensus timestamps in seconds, not block counts. The shared SDK
generates a fresh attempt identifier for answer/advance transactions, so an
earlier rejected request cannot poison a later legitimate retry. Economics and
windows are policy values; an order cannot override them.

## Application integration

- `zkpi-committee` supplies existing hybrid keys, durable node proposal signing,
  canonical admission verification, the QOMM quote adapter and an explicit
  optimistic quote authorization variant. Joint quote encoding remains intact.
- `zkpi-defmi-sdk::optimistic::OptimisticClient` submits native transactions,
  reads claims and drives challenges. `await_finality` requests the original
  proof only when a challenge is observed.
- QOMM uses `AssuranceSelection` in its gateway. Set
  `ZKPI_ASSURANCE_MODE=optimistic`, `ZKPI_OPTIMISTIC_POLICY_ID=<32-byte hex>` and,
  optionally, `ZKPI_OPTIMISTIC_PROPOSER_PARTY=<one-based party>` after enrolling
  and funding the policy. The private MPC execution still runs. Progress emits
  provisional claim metadata, while final settlement waits for canonical
  finality. The HTTP response continues to wait for settlement.
- OCLOB exposes `OclobService::prepare_optimistic_submit`, returning a pending
  execution before book mutation. Its `challenge_proof` uses the existing
  committee transition evidence; `finalize` requires canonical finality and an
  unchanged base book. `OptimisticAvalancheGateway` submits the prepared account
  settlement with its finality reference, checks every configured validator's
  state root and reads back account commitments and sequences before the service
  applies its private book. The ordinary account gateway refuses optimistic
  batches. Native note fills expose a separate finality binding helper before
  producing a monetary certificate. The OCLOB verifier is installed by validator
  configuration through `oclob-avalanche-vm`, not supplied by a transaction.

QOMM challenges use the existing complete quote proof. OCLOB challenges use its
existing 5-of-7 signed transition verification boundary; this is not a new
mathematical zero-knowledge proof. Range, reservation and DvP checks remain
separate and mandatory.

## Current limits

This is an opt-in research implementation. Operators must arrange challenger
availability and retain the existing proof inputs through the response window.
Node proposal records survive restart, but existing volatile proof jobs are not
made resumable by this crate; an unavailable response can therefore forfeit the
bond. There is no production economic configuration or production funding automation.
QOMM and OCLOB browser selectors use this shared protocol; their optional
challenge controls require the explicit public-development configuration.
The OCLOB browser now requires five native validators in both modes and has
no in-process settlement fallback. Its private coordinator book does not yet
have restart recovery, so reuse of a browser state directory is rejected.
See each application's docs/OPTIMISTIC_BROWSER_JA.md for operating instructions.
Live service acceptance is tracked separately from
single-process protocol observations in the project evidence records.

## Reproducing the isolated examples

The `oclob-avalanche-vm` package's `shared-optimistic` example exercises both registered
application verifiers through five native validators: unchallenged, defended,
contradictory and unanswered claims, actual collateral transfers, early
settlement refusal and accepted-block replay. Its `optimistic-service` example
runs seven MP-SPDZ parties for a resting sell and a partially filling buy,
then settles through the service account gateway. These examples use synthetic
assets and public development governance; they do not configure a live venue.

The QOMM `optimistic-policy` example requires the explicit
`--public-development` argument and a loopback development RPC. It enrolls the
actual node application-key fingerprint, credits a synthetic collateral account
and funds escrow through native transactions. Only then should the gateway's
environment select that policy. Keep the same node identity and validator
storage when restarting an enrolled deployment.
Its `--fund-challenger POLICY_ID` and `--challenge CLAIM_ID` operations use a
published development fixture key to exercise a dispute. They are not an
operator key-management interface.
