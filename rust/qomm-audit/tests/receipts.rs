use qomm_audit::receipts::{
    digest, sign_receipt, AuditLedger, BondLedger, Evidence, Fault, NodeReceipt, SlotSpec, GENESIS,
};
use std::collections::BTreeMap;
use std::sync::Arc;
use zkfmi_crypto::{hybrid::signature::HybridSigner, traits::Signer};

const NODES: u32 = 7;
const QUORUM: usize = 5;

fn keys() -> BTreeMap<u32, Arc<HybridSigner>> {
    (0..NODES)
        .map(|node| (node, Arc::new(HybridSigner::generate().unwrap())))
        .collect()
}

fn ledger(keys: &BTreeMap<u32, Arc<HybridSigner>>) -> AuditLedger {
    AuditLedger::new(
        keys.iter()
            .map(|(node, key)| (*node, key.public_key()))
            .collect(),
    )
}

fn makers() -> [u8; 32] {
    let names = (0..16)
        .map(|index| format!("MM-{index}"))
        .collect::<Vec<_>>();
    let mut parts = vec![b"makers".as_slice()];
    parts.extend(names.iter().map(|name| name.as_bytes()));
    digest(&parts)
}

fn spec(slot: u64) -> SlotSpec {
    SlotSpec {
        slot,
        mm_set_digest: makers(),
        market_digest: digest(&[b"market", &slot.to_be_bytes()]),
        deadline: 100 * slot + 50,
        required_receipts: QUORUM,
    }
}

fn honest_round(
    keys: &BTreeMap<u32, Arc<HybridSigner>>,
    ledger: &mut AuditLedger,
    slot: u64,
    previous: [u8; 32],
    skip: &[u32],
) -> ([u8; 32], [u8; 32]) {
    let spec = spec(slot);
    ledger.open_slot(spec.clone());
    let result = digest(&[b"result", &slot.to_be_bytes()]);
    let state = digest(&[b"state", &previous, &result]);
    for node in 0..NODES {
        if !skip.contains(&node) {
            ledger.record(
                sign_receipt(
                    &keys[&node],
                    node,
                    &spec,
                    previous,
                    state,
                    result,
                    100 * slot + 10,
                    None,
                )
                .unwrap(),
                None,
            );
        }
    }
    (result, state)
}

#[test]
fn honest_run_has_no_evidence_and_receipts_hide_real_vs_cover() {
    let keys = keys();
    let mut ledger = ledger(&keys);
    let mut previous = GENESIS;
    for slot in 0..4 {
        honest_round(&keys, &mut ledger, slot, previous, &[]);
        let (state, found) = ledger.settle(slot, 100 * slot + 60).unwrap();
        assert!(found.is_empty());
        previous = state.unwrap();
    }
    assert!(ledger.evidence.is_empty());

    let spec = spec(9);
    let real = sign_receipt(
        &keys[&0],
        0,
        &spec,
        GENESIS,
        digest(&[b"state-real"]),
        digest(&[b"result-real"]),
        10,
        None,
    )
    .unwrap();
    let cover = sign_receipt(
        &keys[&1],
        1,
        &spec,
        GENESIS,
        digest(&[b"state-cover"]),
        digest(&[b"result-cover"]),
        10,
        None,
    )
    .unwrap();
    assert_eq!(real.result_digest.len(), cover.result_digest.len());
    assert_eq!(real.signature.clone().len(), cover.signature.clone().len());
}

#[test]
fn equivocation_omission_stale_state_and_fork_name_only_the_faulty_node() {
    let keys = keys();
    let mut ledger = ledger(&keys);
    let slot0 = spec(0);
    ledger.open_slot(slot0.clone());
    let result = digest(&[b"result"]);
    let majority = digest(&[b"state", &GENESIS, &result]);
    for node in 0..NODES {
        let state = if node == 2 {
            digest(&[b"fork"])
        } else {
            majority
        };
        let maker_set = (node == 4).then(|| digest(&[b"short makers"]));
        ledger.record(
            sign_receipt(
                &keys[&node],
                node,
                &slot0,
                GENESIS,
                state,
                result,
                10,
                maker_set,
            )
            .unwrap(),
            Some(10),
        );
    }
    let other = digest(&[b"result-other"]);
    let found = ledger.record(
        sign_receipt(
            &keys[&3],
            3,
            &slot0,
            GENESIS,
            digest(&[b"state", &GENESIS, &other]),
            other,
            11,
            None,
        )
        .unwrap(),
        Some(11),
    );
    let equivocation = found
        .iter()
        .find(|item| item.fault == Fault::Equivocation)
        .unwrap();
    assert_eq!(equivocation.node, 3);
    assert_eq!(equivocation.exhibits.len(), 2);
    assert_ne!(
        equivocation.exhibits[0].content_digest(),
        equivocation.exhibits[1].content_digest()
    );
    assert!(ledger
        .evidence
        .iter()
        .any(|item| item.fault == Fault::OmittedMakers && item.node == 4));

    let (settled, found) = ledger.settle(0, 60).unwrap();
    assert_eq!(settled, Some(majority));
    assert!(found
        .iter()
        .any(|item| item.fault == Fault::ForkedState && item.node == 2));

    let slot1 = spec(1);
    ledger.open_slot(slot1.clone());
    let stale = sign_receipt(
        &keys[&5],
        5,
        &slot1,
        GENESIS,
        digest(&[b"next"]),
        digest(&[b"next-result"]),
        110,
        None,
    )
    .unwrap();
    let found = ledger.record(stale, Some(110));
    assert!(found
        .iter()
        .any(|item| item.fault == Fault::StaleState && item.node == 5));
}

#[test]
fn deadline_and_quorum_fail_closed_and_arrival_time_defeats_backdating() {
    let keys = keys();
    let mut ledger = ledger(&keys);
    honest_round(&keys, &mut ledger, 0, GENESIS, &[1, 2, 3]);
    let (settled, found) = ledger.settle(0, 60).unwrap();
    assert!(settled.is_none());
    assert_eq!(ledger.settled_state(0), GENESIS);
    assert!(found
        .iter()
        .any(|item| item.fault == Fault::MissingReceipt && item.node == -1));

    let keys = (0..3)
        .map(|node| (node, Arc::new(HybridSigner::generate().unwrap())))
        .collect::<BTreeMap<_, _>>();
    let mut backdating_ledger = crate::ledger(&keys);
    let spec = SlotSpec {
        slot: 1,
        market_digest: [b'm'; 32],
        deadline: 100,
        mm_set_digest: [b's'; 32],
        required_receipts: 3,
    };
    backdating_ledger.open_slot(spec.clone());
    for node in [0, 1] {
        backdating_ledger.record(
            sign_receipt(
                &keys[&node],
                node,
                &spec,
                GENESIS,
                [b'n'; 32],
                [b'r'; 32],
                50,
                None,
            )
            .unwrap(),
            Some(50),
        );
    }
    backdating_ledger.record(
        sign_receipt(
            &keys[&2], 2, &spec, GENESIS, [b'n'; 32], [b'r'; 32], 99, None,
        )
        .unwrap(),
        Some(150),
    );
    let (_, found) = backdating_ledger.settle(1, 150).unwrap();
    assert!(found
        .iter()
        .any(|item| item.fault == Fault::MissingReceipt && item.node == 2));
    assert!(found
        .iter()
        .any(|item| item.fault == Fault::MissingReceipt && item.node == -1));
}

#[test]
fn signatures_bind_timestamp_market_and_deadline() {
    let keys = keys();
    let mut ledger = ledger(&keys);
    let spec = spec(0);
    ledger.open_slot(spec.clone());
    let genuine = sign_receipt(
        &keys[&0],
        0,
        &spec,
        GENESIS,
        digest(&[b"s"]),
        digest(&[b"r"]),
        spec.deadline + 100,
        None,
    )
    .unwrap();
    let mut moved = genuine.clone();
    moved.emitted_at = 1;
    assert!(ledger
        .record(moved, Some(1))
        .iter()
        .any(|item| item.fault == Fault::BadSignature));

    for mutation in 0..2 {
        let mut moved = genuine.clone();
        if mutation == 0 {
            moved.market_digest = digest(&[b"another market"]);
        } else {
            moved.deadline += 10_000;
        }
        assert!(ledger
            .record(moved, Some(1))
            .iter()
            .any(|item| item.fault == Fault::BadSignature));
    }

    for index in [0, 64] {
        let mut moved = genuine.clone();
        moved.signature[index] ^= 1;
        assert!(ledger
            .record(moved, Some(1))
            .iter()
            .any(|item| item.fault == Fault::BadSignature));
    }
    let mut stripped = genuine.clone();
    stripped.signature.truncate(64);
    assert!(ledger
        .record(stripped, Some(1))
        .iter()
        .any(|item| item.fault == Fault::BadSignature));
    let mut forged: NodeReceipt = genuine;
    forged.node = 1;
    assert!(ledger
        .record(forged, Some(1))
        .iter()
        .any(|item| item.fault == Fault::BadSignature && item.node == 1));
}

#[test]
fn wrong_market_is_not_counted_and_slashing_obeys_schedule() {
    let keys = (0..3)
        .map(|node| (node, Arc::new(HybridSigner::generate().unwrap())))
        .collect::<BTreeMap<_, _>>();
    let mut ledger = ledger(&keys);
    let spec = SlotSpec {
        slot: 1,
        market_digest: [b'm'; 32],
        deadline: 100,
        mm_set_digest: [b's'; 32],
        required_receipts: 3,
    };
    ledger.open_slot(spec.clone());
    let mut elsewhere = spec.clone();
    elsewhere.market_digest = [b'x'; 32];
    let found = ledger.record(
        sign_receipt(
            &keys[&0], 0, &elsewhere, GENESIS, [b'n'; 32], [b'r'; 32], 50, None,
        )
        .unwrap(),
        Some(50),
    );
    assert!(found
        .iter()
        .any(|item| item.detail.contains("market other than")));

    let mut bonds = BondLedger::new(BTreeMap::from([(0, 900_000)]));
    let applied = bonds.apply(&[Evidence::new(Fault::Equivocation, 0, 1, "double signed")]);
    assert_eq!(applied[0].amount, 900_000);
    assert_eq!(bonds.bonds[&0], 0);
    assert!(bonds
        .apply(&[Evidence::new(Fault::StaleState, 0, 2, "stale")])
        .is_empty());

    let mut venue = BondLedger::new(BTreeMap::from([(0, 100_000)]));
    assert!(venue
        .apply(&[Evidence::new(Fault::MissingReceipt, -1, 0, "quorum short",)])
        .is_empty());
    assert_eq!(venue.bonds[&0], 100_000);
}
