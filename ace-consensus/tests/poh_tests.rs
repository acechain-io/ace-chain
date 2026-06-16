use ace_consensus::poh::PohChain;

#[test]
fn initial_hash_is_seed() {
    let seed = [42u8; 32];
    let poh = PohChain::new(seed);
    assert_eq!(poh.current_hash(), seed);
    assert_eq!(poh.tick_count(), 0);
}

#[test]
fn tick_changes_hash() {
    let mut poh = PohChain::new([0u8; 32]);
    let before = poh.current_hash();
    let after = poh.tick();
    assert_ne!(before, after);
    assert_eq!(poh.current_hash(), after);
    assert_eq!(poh.tick_count(), 1);
}

#[test]
fn ticks_are_sequential() {
    let mut poh = PohChain::new([1u8; 32]);
    let h1 = poh.tick();
    let h2 = poh.tick();
    let h3 = poh.tick();

    // All different
    assert_ne!(h1, h2);
    assert_ne!(h2, h3);
    assert_ne!(h1, h3);
    assert_eq!(poh.tick_count(), 3);
}

#[test]
fn record_mixes_data() {
    let seed = [0u8; 32];
    let mut poh1 = PohChain::new(seed);
    let mut poh2 = PohChain::new(seed);

    let h_tick = poh1.tick();
    let h_record = poh2.record(b"hello");

    // tick() and record("hello") should produce different hashes
    assert_ne!(h_tick, h_record);
}

#[test]
fn record_is_deterministic() {
    let seed = [7u8; 32];
    let mut poh1 = PohChain::new(seed);
    let mut poh2 = PohChain::new(seed);

    poh1.tick();
    poh2.tick();

    let h1 = poh1.record(b"block_data");
    let h2 = poh2.record(b"block_data");
    assert_eq!(h1, h2, "same sequence must produce same hash");
}

#[test]
fn different_data_different_hash() {
    let seed = [0u8; 32];
    let mut poh1 = PohChain::new(seed);
    let mut poh2 = PohChain::new(seed);

    let h1 = poh1.record(b"data_a");
    let h2 = poh2.record(b"data_b");
    assert_ne!(h1, h2);
}

#[test]
fn tick_count_increments_for_both_operations() {
    let mut poh = PohChain::new([0u8; 32]);
    poh.tick();
    poh.record(b"x");
    poh.tick();
    assert_eq!(poh.tick_count(), 3);
}
