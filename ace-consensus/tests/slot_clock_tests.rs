use ace_consensus::slot_clock::SlotClock;
use ace_runtime::config::SLOT_DURATION_MS;

#[test]
fn current_slot_after_genesis() {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // Genesis 10 seconds ago
    let clock = SlotClock::new(now_ms - 10_000);
    let slot = clock.current_slot();
    let expected_min = 10_000 / SLOT_DURATION_MS;
    assert!(
        slot >= expected_min,
        "10 seconds / {SLOT_DURATION_MS}ms = {expected_min} slots, got {slot}"
    );
}

#[test]
fn current_slot_at_genesis_is_zero() {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let clock = SlotClock::new(now_ms);
    let slot = clock.current_slot();
    assert_eq!(slot, 0);
}

#[test]
fn slot_start_time() {
    let genesis = 1_000_000u64;
    let clock = SlotClock::new(genesis);

    assert_eq!(clock.slot_start_time_ms(0), genesis);
    assert_eq!(clock.slot_start_time_ms(1), genesis + SLOT_DURATION_MS);
    assert_eq!(
        clock.slot_start_time_ms(10),
        genesis + 10 * SLOT_DURATION_MS
    );
}

#[test]
fn time_until_next_slot_is_bounded() {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let clock = SlotClock::new(now_ms - 5_000);
    let remaining = clock.time_until_next_slot_ms();
    assert!(
        remaining <= SLOT_DURATION_MS,
        "remaining should be <= {SLOT_DURATION_MS}ms, got {remaining}"
    );
}

#[test]
fn genesis_time_accessor() {
    let clock = SlotClock::new(42);
    assert_eq!(clock.genesis_time_ms(), 42);
}

#[test]
fn future_genesis_gives_slot_zero() {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // Genesis 1 hour in the future
    let clock = SlotClock::new(now_ms + 3_600_000);
    let slot = clock.current_slot();
    assert_eq!(slot, 0, "future genesis should saturate to slot 0");
}
