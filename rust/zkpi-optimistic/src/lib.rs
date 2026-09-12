//! Shared optimistic execution assurance for MPC applications.
//!
//! This is a deterministic state machine for a consensus/escrow host. Timestamps,
//! enrolled policies and funded bonds MUST come from that host, never an RPC
//! caller. It never reconstructs a witness or treats a signature as a proof.
//! A challenge demands the application's existing, context-bound proof. An
//! invalid proof is rejected; only a verified contradictory result or failure
//! to answer by the deadline forfeits the proposer bond.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub type Digest32 = [u8; 32];

/// Canonical command bytes shared by the ledger and its application clients.
pub fn command_digest<T: Serialize>(operation: &str, value: &T) -> Result<Digest32, String> {
    digest(b"DEFMI:OPTIMISTIC:COMMAND:v1", &(operation, value))
}

/// Transfer from an explicitly public host collateral account. The host must
/// authenticate it and check the opening against the existing account balance.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BondTransfer {
    pub owner: Digest32,
    pub asset: Digest32,
    pub amount: u64,
    pub before_balance: u64,
    pub blinding: Digest32,
    pub withdraw: bool,
}

/// The node library supplies its existing enrolled hybrid application key.
/// This abstraction avoids a dependency cycle or a second key implementation.
pub trait ClaimSigner {
    fn identity(&self) -> Digest32;
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String>;
}

/// Implemented by the trusted host using its enrolled authentication scheme.
pub trait ClaimAuthentication {
    fn verify(&self, identity: Digest32, message: &[u8], signature: &[u8]) -> Result<(), String>;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssuranceMode {
    #[default]
    JointProof,
    Optimistic,
}

/// Caller-selected option; collateral sizes and time windows are ALWAYS read
/// from the enrolled policy, never overridden by an order request.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum AssuranceSelection {
    #[default]
    JointProof,
    Optimistic {
        policy: Digest32,
        proposer_party: usize,
    },
}

impl AssuranceSelection {
    pub fn from_environment() -> Result<Self, String> {
        match std::env::var("ZKPI_ASSURANCE_MODE").as_deref() {
            Err(std::env::VarError::NotPresent) | Ok("joint_proof") => Ok(Self::JointProof),
            Ok("optimistic") => {
                let raw = std::env::var("ZKPI_OPTIMISTIC_POLICY_ID")
                    .map_err(|_| "optimistic mode requires ZKPI_OPTIMISTIC_POLICY_ID")?;
                let policy = hex::decode(raw)
                    .map_err(|_| "optimistic policy ID is not hex")?
                    .try_into()
                    .map_err(|_| "optimistic policy ID is not 32 bytes")?;
                let proposer_party = std::env::var("ZKPI_OPTIMISTIC_PROPOSER_PARTY")
                    .unwrap_or_else(|_| "1".into())
                    .parse::<usize>()
                    .map_err(|_| "optimistic proposer party is not an integer")?;
                if proposer_party == 0 {
                    return Err("optimistic proposer party is one-based".into());
                }
                Ok(Self::Optimistic {
                    policy,
                    proposer_party,
                })
            }
            _ => Err("ZKPI_ASSURANCE_MODE must be joint_proof or optimistic".into()),
        }
    }
}

/// Application-neutral identity. The verifier must bind every field to its
/// own canonical public inputs, including the complete admitted population.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionContext {
    pub network: Digest32,
    pub application: Digest32,
    pub verifier: Digest32,
    pub job: Digest32,
    pub input_root: Digest32,
    pub before_state: Digest32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OptimisticPolicy {
    pub network: Digest32,
    pub application: Digest32,
    pub verifier: Digest32,
    pub proposer: Digest32,
    pub bond_asset: Digest32,
    pub proposer_bond: u64,
    pub challenger_bond: u64,
    pub challenge_window_seconds: u64,
    pub response_window_seconds: u64,
}

impl OptimisticPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if [
            self.network,
            self.application,
            self.verifier,
            self.proposer,
            self.bond_asset,
        ]
        .contains(&[0; 32])
            || self.proposer_bond == 0
            || self.challenger_bond == 0
            || self.challenge_window_seconds == 0
            || self.response_window_seconds == 0
        {
            return Err("optimistic policy has an empty identity, bond or deadline".into());
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<Digest32, String> {
        self.validate()?;
        digest(b"zkFMI:optimistic:policy:v1", self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proposal {
    pub policy: Digest32,
    pub context: ExecutionContext,
    pub output_root: Digest32,
    /// Deadline for accepting this signed proposal, not the challenge deadline.
    pub valid_until: u64,
    pub signature: Vec<u8>,
}

impl Proposal {
    pub fn signed(
        policy: &OptimisticPolicy,
        context: ExecutionContext,
        output_root: Digest32,
        valid_until: u64,
        key: &impl ClaimSigner,
    ) -> Result<Self, String> {
        if key.identity() != policy.proposer {
            return Err("optimistic proposer is not enrolled by the policy".into());
        }
        let mut proposal = Self {
            policy: policy.digest()?,
            context,
            output_root,
            valid_until,
            signature: Vec::new(),
        };
        proposal.signature = key.sign(&proposal.signing_digest()?)?;
        Ok(proposal)
    }

    pub fn signing_digest(&self) -> Result<Digest32, String> {
        digest(
            b"zkFMI:optimistic:proposal:v1",
            &(
                self.policy,
                &self.context,
                self.output_root,
                self.valid_until,
            ),
        )
    }

    pub fn id(&self) -> Result<Digest32, String> {
        self.signing_digest()
    }

    pub fn verify(
        &self,
        policy: &OptimisticPolicy,
        now: u64,
        authentication: &impl ClaimAuthentication,
    ) -> Result<(), String> {
        if self.policy != policy.digest()?
            || self.context.network != policy.network
            || self.context.application != policy.application
            || self.context.verifier != policy.verifier
            || [
                self.context.job,
                self.context.input_root,
                self.context.before_state,
                self.output_root,
            ]
            .contains(&[0; 32])
            || now > self.valid_until
        {
            return Err(
                "optimistic proposal has another scope, empty binding or expired admission".into(),
            );
        }
        authentication.verify(policy.proposer, &self.signing_digest()?, &self.signature)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub claim: Digest32,
    pub challenger: Digest32,
    pub signature: Vec<u8>,
}

impl Challenge {
    pub fn signed(claim: Digest32, key: &impl ClaimSigner) -> Result<Self, String> {
        let mut challenge = Self {
            claim,
            challenger: key.identity(),
            signature: Vec::new(),
        };
        challenge.signature = key.sign(&challenge.signing_digest()?)?;
        Ok(challenge)
    }

    fn signing_digest(&self) -> Result<Digest32, String> {
        digest(
            b"zkFMI:optimistic:challenge:v1",
            &(self.claim, self.challenger),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClaimStatus {
    Pending,
    Challenged {
        challenger: Digest32,
        response_deadline: u64,
    },
    Proven {
        proof: Digest32,
    },
    Finalized {
        proof: Option<Digest32>,
    },
    Rejected {
        challenger: Digest32,
        proof: Option<Digest32>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    pub proposal: Proposal,
    pub policy: OptimisticPolicy,
    pub accepted_at: u64,
    pub challenge_deadline: u64,
    pub status: ClaimStatus,
}

/// Proof verification is supplied by the canonical application verifier in
/// the hosting ledger, not selected or asserted by the submitting party.
pub trait ChallengeVerifier {
    fn verifier_id(&self) -> Digest32;
    fn verify(&self, context: &ExecutionContext, proof: &[u8]) -> Result<Digest32, String>;
}

/// Funds here are escrowed funds: the ledger adapter must debit the actual
/// owner's balance when funding and credit it when withdrawing. This module
/// deliberately provides no untrusted "deposit amount" RPC.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BondAccount {
    pub available: u64,
    pub locked: u64,
}

/// Deterministic serializable state. Its enclosing ledger owns atomic commit,
/// authenticated funding, canonical consensus time, policy enrollment and recovery.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OptimisticState {
    policies: BTreeMap<String, OptimisticPolicy>,
    executions: BTreeMap<String, RegisteredExecution>,
    claims: BTreeMap<String, Claim>,
    jobs: BTreeMap<String, Digest32>,
    bonds: BTreeMap<String, BondAccount>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisteredExecution {
    pub policy: Digest32,
    pub context: ExecutionContext,
    pub valid_until: u64,
}

impl OptimisticState {
    /// Governance-only enrollment. The caller must authenticate this operation
    /// using the host's existing governance transaction, not the proposer key.
    pub fn enroll_policy(&mut self, policy: OptimisticPolicy) -> Result<Digest32, String> {
        let id = policy.digest()?;
        if self.policies.contains_key(&hex::encode(id)) {
            return Err("optimistic policy is already enrolled".into());
        }
        self.policies.insert(hex::encode(id), policy);
        Ok(id)
    }

    pub fn policy(&self, id: &Digest32) -> Option<&OptimisticPolicy> {
        self.policies.get(&hex::encode(id))
    }

    pub fn policies(&self) -> impl Iterator<Item = &OptimisticPolicy> {
        self.policies.values()
    }

    /// Register canonical admitted inputs before a proposer can assert an
    /// output. The hosting application's admission/governance path owns this
    /// operation; a proposer cannot choose its own truth population or verifier.
    pub fn register_execution(&mut self, execution: RegisteredExecution) -> Result<(), String> {
        let policy = self
            .policy(&execution.policy)
            .ok_or("execution policy is not enrolled")?;
        if execution.context.network != policy.network
            || execution.context.application != policy.application
            || execution.context.verifier != policy.verifier
            || execution.valid_until == 0
            || [
                execution.context.job,
                execution.context.input_root,
                execution.context.before_state,
            ]
            .contains(&[0; 32])
        {
            return Err("execution does not match enrolled scope".into());
        }
        let id = job_key(&execution.context)?;
        if self.executions.contains_key(&id) {
            return Err("execution inputs are already registered".into());
        }
        self.executions.insert(id, execution);
        Ok(())
    }

    pub fn claim(&self, id: &Digest32) -> Option<&Claim> {
        self.claims.get(&hex::encode(id))
    }

    pub fn bond(&self, asset: Digest32, owner: Digest32) -> BondAccount {
        self.bonds
            .get(&bond_key(asset, owner))
            .cloned()
            .unwrap_or_default()
    }

    /// Called only after the host debits real collateral in the SAME atomic
    /// transaction. A failure must roll back both sides.
    pub fn credit_escrow(
        &mut self,
        asset: Digest32,
        owner: Digest32,
        amount: u64,
    ) -> Result<(), String> {
        if asset == [0; 32] || owner == [0; 32] || amount == 0 {
            return Err("invalid optimistic escrow credit".into());
        }
        let mut account = self.bond(asset, owner);
        account.available = account
            .available
            .checked_add(amount)
            .ok_or("escrow overflow")?;
        self.bonds.insert(bond_key(asset, owner), account);
        Ok(())
    }

    /// The host authenticates owner and credits the underlying asset atomically.
    pub fn withdraw_escrow(
        &mut self,
        asset: Digest32,
        owner: Digest32,
        amount: u64,
    ) -> Result<(), String> {
        if amount == 0 {
            return Err("zero escrow withdrawal".into());
        }
        let mut account = self.bond(asset, owner);
        account.available = account
            .available
            .checked_sub(amount)
            .ok_or("insufficient unlocked escrow")?;
        self.bonds.insert(bond_key(asset, owner), account);
        Ok(())
    }

    pub fn propose(
        &mut self,
        proposal: Proposal,
        now: u64,
        authentication: &impl ClaimAuthentication,
    ) -> Result<Digest32, String> {
        let policy = self
            .policy(&proposal.policy)
            .cloned()
            .ok_or("optimistic policy is not enrolled")?;
        proposal.verify(&policy, now, authentication)?;
        let id = proposal.id()?;
        let job = job_key(&proposal.context)?;
        let execution = self
            .executions
            .get(&job)
            .ok_or("optimistic execution inputs are not registered")?;
        if execution.context != proposal.context
            || execution.policy != proposal.policy
            || proposal.valid_until > execution.valid_until
            || now
                .checked_add(policy.challenge_window_seconds)
                .and_then(|value| value.checked_add(policy.response_window_seconds))
                .is_none_or(|deadline| deadline > execution.valid_until)
        {
            return Err(
                "proposal differs from admitted inputs or exceeds the execution deadline".into(),
            );
        }
        if self.claims.contains_key(&hex::encode(id)) || self.jobs.contains_key(&job) {
            return Err("optimistic execution already has a claim".into());
        }
        let challenge_deadline = now
            .checked_add(policy.challenge_window_seconds)
            .ok_or("challenge now overflow")?;
        let mut next = self.clone();
        next.lock(policy.bond_asset, policy.proposer, policy.proposer_bond)?;
        next.claims.insert(
            hex::encode(id),
            Claim {
                proposal,
                policy: policy.clone(),
                accepted_at: now,
                challenge_deadline,
                status: ClaimStatus::Pending,
            },
        );
        next.jobs.insert(job, id);
        *self = next;
        Ok(id)
    }

    pub fn challenge(
        &mut self,
        request: Challenge,
        now: u64,
        authentication: &impl ClaimAuthentication,
    ) -> Result<(), String> {
        authentication.verify(
            request.challenger,
            &request.signing_digest()?,
            &request.signature,
        )?;
        let mut claim = self
            .claim(&request.claim)
            .cloned()
            .ok_or("unknown optimistic claim")?;
        if claim.status != ClaimStatus::Pending
            || now < claim.accepted_at
            || now >= claim.challenge_deadline
        {
            return Err("optimistic claim is outside its challenge window".into());
        }
        if request.challenger == claim.policy.proposer {
            return Err("proposer cannot occupy its own challenge slot".into());
        }
        let response_deadline = now
            .checked_add(claim.policy.response_window_seconds)
            .ok_or("response now overflow")?;
        let mut next = self.clone();
        next.lock(
            claim.policy.bond_asset,
            request.challenger,
            claim.policy.challenger_bond,
        )?;
        claim.status = ClaimStatus::Challenged {
            challenger: request.challenger,
            response_deadline,
        };
        next.claims.insert(hex::encode(request.claim), claim);
        *self = next;
        Ok(())
    }

    /// Anyone may relay a valid proof. The verifier is bound to the enrolled
    /// policy, context and input snapshot. Invalid bytes never cause a slash.
    pub fn answer<V: ChallengeVerifier + ?Sized>(
        &mut self,
        id: Digest32,
        proof: &[u8],
        verifier: &V,
        now: u64,
    ) -> Result<(), String> {
        let mut claim = self.claim(&id).cloned().ok_or("unknown optimistic claim")?;
        let (challenger, response_deadline) = match claim.status {
            ClaimStatus::Challenged {
                challenger,
                response_deadline,
            } => (challenger, response_deadline),
            _ => return Err("optimistic claim has no unresolved challenge".into()),
        };
        if now < claim.accepted_at
            || now >= response_deadline
            || verifier.verifier_id() != claim.policy.verifier
        {
            return Err("challenge proof has a late timestamp or another verifier".into());
        }
        let output = verifier.verify(&claim.proposal.context, proof)?;
        let evidence: Digest32 = Sha256::digest(proof).into();
        let valid = output == claim.proposal.output_root;
        let mut next = self.clone();
        claim.status = if valid {
            // A valid defense resolves the dispute but does not accelerate the
            // user's selected finalization window or release the proposer bond.
            next.award(
                claim.policy.bond_asset,
                challenger,
                claim.policy.proposer,
                claim.policy.challenger_bond,
            )?;
            ClaimStatus::Proven { proof: evidence }
        } else {
            next.resolve_bonds(&claim.policy, challenger, false)?;
            ClaimStatus::Rejected {
                challenger,
                proof: Some(evidence),
            }
        };
        next.claims.insert(hex::encode(id), claim);
        *self = next;
        Ok(())
    }

    /// Deterministic permissionless advancement using canonical ledger timestamp.
    pub fn advance(&mut self, id: Digest32, now: u64) -> Result<(), String> {
        let mut claim = self.claim(&id).cloned().ok_or("unknown optimistic claim")?;
        let mut next = self.clone();
        match claim.status {
            ClaimStatus::Pending if now >= claim.challenge_deadline => {
                next.unlock(
                    claim.policy.bond_asset,
                    claim.policy.proposer,
                    claim.policy.proposer_bond,
                )?;
                claim.status = ClaimStatus::Finalized { proof: None };
            }
            ClaimStatus::Proven { proof } if now >= claim.challenge_deadline => {
                next.unlock(
                    claim.policy.bond_asset,
                    claim.policy.proposer,
                    claim.policy.proposer_bond,
                )?;
                claim.status = ClaimStatus::Finalized { proof: Some(proof) };
            }
            ClaimStatus::Challenged {
                challenger,
                response_deadline,
            } if now >= response_deadline => {
                next.resolve_bonds(&claim.policy, challenger, false)?;
                claim.status = ClaimStatus::Rejected {
                    challenger,
                    proof: None,
                };
            }
            _ => return Err("optimistic deadline has not elapsed or claim is terminal".into()),
        }
        next.claims.insert(hex::encode(id), claim);
        *self = next;
        Ok(())
    }

    /// Settlement must call this on authoritative ledger state with its own
    /// expected context and output, never trust a client-carried status field.
    pub fn require_finalized(
        &self,
        id: Digest32,
        context: &ExecutionContext,
        output_root: Digest32,
    ) -> Result<&Claim, String> {
        let claim = self.claim(&id).ok_or("unknown optimistic claim")?;
        if &claim.proposal.context != context
            || claim.proposal.output_root != output_root
            || !matches!(claim.status, ClaimStatus::Finalized { .. })
        {
            return Err("optimistic execution is not finalized for this settlement".into());
        }
        Ok(claim)
    }

    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
            && self.executions.is_empty()
            && self.claims.is_empty()
            && self.jobs.is_empty()
            && self.bonds.is_empty()
    }

    /// Run when loading snapshots and before the host commits a transition.
    /// The enclosing consensus snapshot still supplies authenticity and rollback
    /// protection; structural checks alone are not a signature on local files.
    pub fn validate(&self, authentication: &impl ClaimAuthentication) -> Result<(), String> {
        for (id, policy) in &self.policies {
            if *id != hex::encode(policy.digest()?) {
                return Err("optimistic policy index mismatch".into());
            }
        }
        for (id, execution) in &self.executions {
            let policy = self
                .policy(&execution.policy)
                .ok_or("registered execution policy absent")?;
            if *id != job_key(&execution.context)?
                || execution.valid_until == 0
                || execution.context.network != policy.network
                || execution.context.application != policy.application
                || execution.context.verifier != policy.verifier
                || [
                    execution.context.job,
                    execution.context.input_root,
                    execution.context.before_state,
                ]
                .contains(&[0; 32])
            {
                return Err("registered execution snapshot mismatch".into());
            }
        }
        let mut jobs = BTreeMap::new();
        let mut locked: BTreeMap<String, u64> = BTreeMap::new();
        for (id, claim) in &self.claims {
            let policy = self
                .policy(&claim.proposal.policy)
                .ok_or("claim policy absent")?;
            if policy != &claim.policy
                || *id != hex::encode(claim.proposal.id()?)
                || claim.challenge_deadline
                    != claim
                        .accepted_at
                        .checked_add(policy.challenge_window_seconds)
                        .ok_or("challenge overflow")?
            {
                return Err("optimistic claim index or enrolled policy mismatch".into());
            }
            claim
                .proposal
                .verify(policy, claim.accepted_at, authentication)?;
            let execution = self
                .executions
                .get(&job_key(&claim.proposal.context)?)
                .ok_or("claim execution absent")?;
            if execution.context != claim.proposal.context
                || execution.policy != claim.proposal.policy
                || claim.proposal.valid_until > execution.valid_until
                || claim
                    .challenge_deadline
                    .checked_add(policy.response_window_seconds)
                    .is_none_or(|end| end > execution.valid_until)
            {
                return Err("claim differs from its registered execution".into());
            }
            if jobs
                .insert(job_key(&claim.proposal.context)?, claim.proposal.id()?)
                .is_some()
            {
                return Err("duplicate optimistic execution".into());
            }
            let mut add_locked = |owner, amount| -> Result<(), String> {
                let entry = locked
                    .entry(bond_key(policy.bond_asset, owner))
                    .or_default();
                *entry = entry
                    .checked_add(amount)
                    .ok_or("snapshot locked collateral overflow")?;
                Ok(())
            };
            match claim.status {
                ClaimStatus::Pending | ClaimStatus::Proven { .. } => {
                    add_locked(policy.proposer, policy.proposer_bond)?
                }
                ClaimStatus::Challenged {
                    challenger,
                    response_deadline,
                } => {
                    let start = response_deadline
                        .checked_sub(policy.response_window_seconds)
                        .ok_or("invalid response window")?;
                    if start < claim.accepted_at
                        || start >= claim.challenge_deadline
                        || challenger == policy.proposer
                    {
                        return Err("invalid persisted challenge".into());
                    }
                    add_locked(policy.proposer, policy.proposer_bond)?;
                    add_locked(challenger, policy.challenger_bond)?;
                }
                _ => {}
            }
        }
        if jobs != self.jobs {
            return Err("optimistic job index mismatch".into());
        }
        for (key, account) in &self.bonds {
            let mut parts = key.split(':');
            let valid_part = |part: Option<&str>| {
                part.is_some_and(|p| {
                    p.len() == 64
                        && p.bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                        && p != "0".repeat(64)
                })
            };
            if !valid_part(parts.next())
                || !valid_part(parts.next())
                || parts.next().is_some()
                || locked.remove(key).unwrap_or(0) != account.locked
            {
                return Err("optimistic collateral snapshot mismatch".into());
            }
        }
        if !locked.is_empty() {
            return Err("optimistic collateral account missing".into());
        }
        Ok(())
    }

    fn lock(&mut self, asset: Digest32, owner: Digest32, amount: u64) -> Result<(), String> {
        let mut account = self.bond(asset, owner);
        account.available = account
            .available
            .checked_sub(amount)
            .ok_or("insufficient optimistic collateral")?;
        account.locked = account
            .locked
            .checked_add(amount)
            .ok_or("locked collateral overflow")?;
        self.bonds.insert(bond_key(asset, owner), account);
        Ok(())
    }

    fn unlock(&mut self, asset: Digest32, owner: Digest32, amount: u64) -> Result<(), String> {
        self.award(asset, owner, owner, amount)
    }

    fn award(
        &mut self,
        asset: Digest32,
        from: Digest32,
        to: Digest32,
        amount: u64,
    ) -> Result<(), String> {
        let mut debit = self.bond(asset, from);
        debit.locked = debit
            .locked
            .checked_sub(amount)
            .ok_or("inconsistent locked collateral")?;
        self.bonds.insert(bond_key(asset, from), debit);
        self.credit_escrow(asset, to, amount)
    }

    fn resolve_bonds(
        &mut self,
        policy: &OptimisticPolicy,
        challenger: Digest32,
        valid: bool,
    ) -> Result<(), String> {
        let beneficiary = if valid { policy.proposer } else { challenger };
        self.award(
            policy.bond_asset,
            policy.proposer,
            beneficiary,
            policy.proposer_bond,
        )?;
        self.award(
            policy.bond_asset,
            challenger,
            beneficiary,
            policy.challenger_bond,
        )
    }
}

fn digest<T: Serialize>(domain: &[u8], value: &T) -> Result<Digest32, String> {
    let bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    Ok(Sha256::new()
        .chain_update(domain)
        .chain_update(bytes)
        .finalize()
        .into())
}

fn job_key(context: &ExecutionContext) -> Result<String, String> {
    Ok(hex::encode(digest(
        b"zkFMI:optimistic:job:v1",
        &(context.network, context.application, context.job),
    )?))
}

fn bond_key(asset: Digest32, owner: Digest32) -> String {
    format!("{}:{}", hex::encode(asset), hex::encode(owner))
}
