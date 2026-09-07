//! Print this machine's published label, the one every artifact records.
//!
//! The Makefile needs it before any measurement runs, and it used to get it by

fn main() {
    println!("{}", zkfmi_measure::hosts::this_host());
}
