//! The deadline's timer, on a plain context: no key, no enclave and no dialog, so these run on any
//! Mac, a virtual one included. Each case takes a fresh context, since a deadline that fires
//! invalidates its own.

use core::panic::AssertUnwindSafe;
use core::time::Duration;
use std::panic::catch_unwind;
use std::thread::sleep;
use std::time::Instant;

use super::Context;

/// Far longer than any case below takes, so a case that sits it out fails on time, not by luck.
const LONG: Duration = Duration::from_secs(10);

/// A bound well under `LONG` for a call that must return at once.
const PROMPT: Duration = Duration::from_secs(1);

#[test]
fn an_operation_that_outlives_the_wait_fires_the_deadline_and_keeps_its_result() {
    let context = Context::silent().unwrap();
    let outcome = context
        .within(Duration::from_millis(50), || {
            sleep(Duration::from_millis(300));
            7
        })
        .unwrap();
    assert_eq!(outcome, (7, true));
}

#[test]
fn an_operation_that_returns_at_once_does_not_sit_out_the_wait() {
    let context = Context::silent().unwrap();
    let start = Instant::now();
    let outcome = context.within(LONG, || 7).unwrap();
    let took = start.elapsed();
    assert_eq!(outcome, (7, false));
    assert!(took < PROMPT, "returned after {took:?}");
}

#[test]
fn an_operation_that_panics_does_not_sit_out_the_wait() {
    let context = Context::silent().unwrap();
    let start = Instant::now();
    let unwound = catch_unwind(AssertUnwindSafe(|| {
        context.within(LONG, || panic!("operation"))
    }));
    let took = start.elapsed();
    assert!(unwound.is_err());
    assert!(took < PROMPT, "unwound after {took:?}");
}
