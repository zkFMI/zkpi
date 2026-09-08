//! Shared threshold proofs, quote relations, recipient openings and KYB.
//! These are consumed by multiple venues and the DeFMI settlement layer;
//! QOMM-specific rule, policy, state and liquidity audits live in QOMM.
pub mod kyb;
pub mod opening_envelope;
pub mod price_limit;
pub mod quote_proof;
pub mod threshold_gadgets;
pub mod threshold_quote;
pub mod threshold_range;
pub mod threshold_sigma;
