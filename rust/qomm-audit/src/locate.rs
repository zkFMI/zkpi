//! Share-location surface.
//!
//! The Berlekamp--Welch implementation was already ported into `zkfmi-zk`, next
//! to the Shamir field implementation it decodes. Re-exporting it avoids a
//! second arithmetic core while preserving the audit crate's public role.

pub use zkfmi_zk::shamir::{capacity, locate, points, reconstruct, share, Verdict};
