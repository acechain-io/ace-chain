//! Crit-bit (radix) tree set of `u64` prices, persisted per market.
//!
//! This is the Serum/OpenBook price-ladder design: insert / remove / find-min
//! / find-max are all O(tree height) ≤ O(64) and touch only a handful of node
//! slots — never a whole-ladder rewrite. Nodes live in a per-market, reuseable
//! arena (free list) so the state footprint stays bounded as levels churn, and
//! all slots live under the market's own account so different markets never
//! contend.
//!
//! Node handle `0` is the null sentinel; real handles start at 1.

use ace_model::account::AccountId;
use ace_model::state_tree::StateTree;
use sha2::{Digest, Sha256};

use crate::state::market_book_id;
use crate::types::{MarketId, OrderSide};

const ROOT_DOMAIN: &[u8] = b"ace-liquid:cb-root:v1";
const NODE_DOMAIN: &[u8] = b"ace-liquid:cb-node:v1";
const ALLOC_DOMAIN: &[u8] = b"ace-liquid:cb-alloc:v1";
const FREELIST_DOMAIN: &[u8] = b"ace-liquid:cb-free:v1";

const TAG_FREE: u8 = 0;
const TAG_INNER: u8 = 1;
const TAG_LEAF: u8 = 2;

enum Node {
    Inner { crit: u8, left: u64, right: u64 },
    Leaf { key: u64 },
}

/// Insert `key` into the (market, side) ladder. No-op if already present.
pub fn insert(state: &mut StateTree, market_id: &MarketId, side: OrderSide, key: u64) {
    let owner = market_book_id(market_id);
    let root = read_root(state, &owner, side);
    if root == 0 {
        let leaf = alloc(state, &owner);
        write_node(state, &owner, leaf, &Node::Leaf { key });
        write_root(state, &owner, side, leaf);
        return;
    }

    let mut p = root;
    while let Node::Inner { crit, left, right } = read_node(state, &owner, p) {
        p = if dir(key, crit) == 0 { left } else { right };
    }
    let leaf_key = match read_node(state, &owner, p) {
        Node::Leaf { key } => key,
        _ => unreachable!("walk must end at a leaf"),
    };
    if leaf_key == key {
        return;
    }

    let cb = highest_bit(key ^ leaf_key);

    let mut link = Link::Root;
    let mut cur = root;
    loop {
        match read_node(state, &owner, cur) {
            Node::Inner { crit, left, right } if crit > cb => {
                let d = dir(key, crit);
                link = Link::Child(cur, d);
                cur = if d == 0 { left } else { right };
            }
            _ => break,
        }
    }

    let new_leaf = alloc(state, &owner);
    write_node(state, &owner, new_leaf, &Node::Leaf { key });
    let new_inner = alloc(state, &owner);
    let d = dir(key, cb);
    let (left, right) = if d == 0 {
        (new_leaf, cur)
    } else {
        (cur, new_leaf)
    };
    write_node(
        state,
        &owner,
        new_inner,
        &Node::Inner {
            crit: cb,
            left,
            right,
        },
    );
    set_link(state, &owner, side, link, new_inner);
}

/// Remove `key` from the (market, side) ladder. No-op if absent. O(tree height).
pub fn remove(state: &mut StateTree, market_id: &MarketId, side: OrderSide, key: u64) {
    let owner = market_book_id(market_id);
    let root = read_root(state, &owner, side);
    if root == 0 {
        return;
    }

    let mut link_p = Link::Root;
    let mut p = root;
    let mut link_q: Option<Link> = None;
    let mut q: u64 = 0;
    let mut qdir = 0usize;
    loop {
        match read_node(state, &owner, p) {
            Node::Inner { crit, left, right } => {
                let d = dir(key, crit);
                link_q = Some(link_p);
                q = p;
                qdir = d;
                link_p = Link::Child(p, d);
                p = if d == 0 { left } else { right };
            }
            Node::Leaf { key: leaf_key } => {
                if leaf_key != key {
                    return;
                }
                break;
            }
        }
    }

    free(state, &owner, p);
    match link_q {
        None => write_root(state, &owner, side, 0),
        Some(link_to_q) => {
            let other = match read_node(state, &owner, q) {
                Node::Inner { left, right, .. } => {
                    if qdir == 0 {
                        right
                    } else {
                        left
                    }
                }
                _ => unreachable!("parent must be inner"),
            };
            set_link(state, &owner, side, link_to_q, other);
            free(state, &owner, q);
        }
    }
}

/// Smallest key in the ladder, if any.
pub fn min(state: &StateTree, market_id: &MarketId, side: OrderSide) -> Option<u64> {
    extreme(state, market_id, side, 0)
}

/// Largest key in the ladder, if any.
pub fn max(state: &StateTree, market_id: &MarketId, side: OrderSide) -> Option<u64> {
    extreme(state, market_id, side, 1)
}

fn extreme(state: &StateTree, market_id: &MarketId, side: OrderSide, child: usize) -> Option<u64> {
    let owner = market_book_id(market_id);
    let mut p = read_root(state, &owner, side);
    if p == 0 {
        return None;
    }
    loop {
        match read_node(state, &owner, p) {
            Node::Inner { left, right, .. } => p = if child == 0 { left } else { right },
            Node::Leaf { key } => return Some(key),
        }
    }
}

// ── Link abstraction ──────────────────────────────────────────────────────

#[derive(Clone, Copy)]
enum Link {
    Root,
    Child(u64, usize),
}

fn set_link(state: &mut StateTree, owner: &AccountId, side: OrderSide, link: Link, value: u64) {
    match link {
        Link::Root => write_root(state, owner, side, value),
        Link::Child(parent, idx) => match read_node(state, owner, parent) {
            Node::Inner { crit, left, right } => {
                let (left, right) = if idx == 0 {
                    (value, right)
                } else {
                    (left, value)
                };
                write_node(state, owner, parent, &Node::Inner { crit, left, right });
            }
            _ => unreachable!("link parent must be inner"),
        },
    }
}

// ── Arena (allocation + free list), per market account ────────────────────

fn alloc(state: &mut StateTree, owner: &AccountId) -> u64 {
    let free_head = read_u64(state, owner, &single_slot(FREELIST_DOMAIN));
    if free_head != 0 {
        let next = match read_node(state, owner, free_head) {
            Node::Leaf { key } => key, // free node reuses the key field for next
            _ => 0,
        };
        write_u64(state, owner, single_slot(FREELIST_DOMAIN), next);
        return free_head;
    }
    let next_handle = read_u64(state, owner, &single_slot(ALLOC_DOMAIN)).max(1);
    write_u64(state, owner, single_slot(ALLOC_DOMAIN), next_handle + 1);
    next_handle
}

fn free(state: &mut StateTree, owner: &AccountId, handle: u64) {
    let free_head = read_u64(state, owner, &single_slot(FREELIST_DOMAIN));
    write_raw_node(state, owner, handle, TAG_FREE, 0, free_head, 0);
    write_u64(state, owner, single_slot(FREELIST_DOMAIN), handle);
}

// ── Node / slot I/O ───────────────────────────────────────────────────────

fn read_root(state: &StateTree, owner: &AccountId, side: OrderSide) -> u64 {
    read_u64(state, owner, &root_slot(side))
}

fn write_root(state: &mut StateTree, owner: &AccountId, side: OrderSide, handle: u64) {
    write_u64(state, owner, root_slot(side), handle);
}

fn read_node(state: &StateTree, owner: &AccountId, handle: u64) -> Node {
    let v = state.get_storage(owner, &node_slot(handle));
    let tag = v[0];
    let a = u64::from_le_bytes(v[8..16].try_into().unwrap());
    let b = u64::from_le_bytes(v[16..24].try_into().unwrap());
    match tag {
        TAG_INNER => Node::Inner {
            crit: v[1],
            left: a,
            right: b,
        },
        TAG_LEAF => Node::Leaf { key: a },
        _ => Node::Leaf { key: a },
    }
}

fn write_node(state: &mut StateTree, owner: &AccountId, handle: u64, node: &Node) {
    match node {
        Node::Inner { crit, left, right } => {
            write_raw_node(state, owner, handle, TAG_INNER, *crit, *left, *right)
        }
        Node::Leaf { key } => write_raw_node(state, owner, handle, TAG_LEAF, 0, *key, 0),
    }
}

fn write_raw_node(
    state: &mut StateTree,
    owner: &AccountId,
    handle: u64,
    tag: u8,
    crit: u8,
    a: u64,
    b: u64,
) {
    let mut value = [0u8; 32];
    value[0] = tag;
    value[1] = crit;
    value[8..16].copy_from_slice(&a.to_le_bytes());
    value[16..24].copy_from_slice(&b.to_le_bytes());
    state.set_storage(owner, node_slot(handle), value);
}

fn dir(key: u64, crit: u8) -> usize {
    ((key >> crit) & 1) as usize
}

fn highest_bit(x: u64) -> u8 {
    debug_assert!(x != 0);
    (63 - x.leading_zeros()) as u8
}

fn root_slot(side: OrderSide) -> [u8; 32] {
    let s = match side {
        OrderSide::Buy => 0u8,
        OrderSide::Sell => 1u8,
    };
    domain_slot(ROOT_DOMAIN, &[s])
}

fn node_slot(handle: u64) -> [u8; 32] {
    domain_slot(NODE_DOMAIN, &handle.to_le_bytes())
}

fn single_slot(domain: &[u8]) -> [u8; 32] {
    domain_slot(domain, &[])
}

fn domain_slot(domain: &[u8], key: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(key);
    let result = hasher.finalize();
    let mut slot = [0u8; 32];
    slot.copy_from_slice(&result);
    slot
}

fn read_u64(state: &StateTree, owner: &AccountId, slot: &[u8; 32]) -> u64 {
    let value = state.get_storage(owner, slot);
    u64::from_le_bytes(value[0..8].try_into().unwrap())
}

fn write_u64(state: &mut StateTree, owner: &AccountId, slot: [u8; 32], value: u64) {
    let mut encoded = [0u8; 32];
    encoded[0..8].copy_from_slice(&value.to_le_bytes());
    state.set_storage(owner, slot, encoded);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::derive_market_id;
    use ace_model::account::AccountId;

    fn mid() -> MarketId {
        derive_market_id(
            &AccountId::from_bytes([1; 32]),
            &AccountId::from_bytes([2; 32]),
        )
    }

    #[test]
    fn insert_min_max_remove() {
        let mut state = StateTree::new();
        let m = mid();
        let side = OrderSide::Buy;

        for p in [50u64, 10, 90, 30, 70, 10, 90] {
            insert(&mut state, &m, side, p);
        }
        assert_eq!(min(&state, &m, side), Some(10));
        assert_eq!(max(&state, &m, side), Some(90));

        remove(&mut state, &m, side, 10);
        assert_eq!(min(&state, &m, side), Some(30));
        remove(&mut state, &m, side, 90);
        assert_eq!(max(&state, &m, side), Some(70));

        remove(&mut state, &m, side, 50);
        assert_eq!(min(&state, &m, side), Some(30));
        assert_eq!(max(&state, &m, side), Some(70));

        remove(&mut state, &m, side, 30);
        remove(&mut state, &m, side, 70);
        assert_eq!(min(&state, &m, side), None);
        assert_eq!(max(&state, &m, side), None);
    }

    #[test]
    fn freed_nodes_are_recycled() {
        let mut state = StateTree::new();
        let m = mid();
        let side = OrderSide::Sell;
        let owner = market_book_id(&m);

        for p in 1..=8u64 {
            insert(&mut state, &m, side, p);
        }
        let high_watermark = read_u64(&state, &owner, &single_slot(ALLOC_DOMAIN));
        for p in 1..=8u64 {
            remove(&mut state, &m, side, p);
        }
        for p in 100..=107u64 {
            insert(&mut state, &m, side, p);
        }
        let after = read_u64(&state, &owner, &single_slot(ALLOC_DOMAIN));
        assert_eq!(
            high_watermark, after,
            "arena should not grow after recycling"
        );
        assert_eq!(min(&state, &m, side), Some(100));
        assert_eq!(max(&state, &m, side), Some(107));
    }

    #[test]
    fn many_levels_sorted() {
        let mut state = StateTree::new();
        let m = mid();
        let side = OrderSide::Buy;
        let mut expected: Vec<u64> = (0..200).map(|i| (i * 7 + 3) % 977).collect();
        for &p in &expected {
            insert(&mut state, &m, side, p);
        }
        expected.sort_unstable();
        expected.dedup();
        assert_eq!(min(&state, &m, side), Some(*expected.first().unwrap()));
        assert_eq!(max(&state, &m, side), Some(*expected.last().unwrap()));
    }
}
