//! Process-wide "is the agent currently working?" signal.
//!
//! `drive_turn_stream` wraps every `Agent::run_turn` invocation. By
//! holding a `BusyGuard` for the lifetime of that wrapper we keep a
//! counter > 0 while any turn is in flight (including nested side-
//! channel turns for reconcile / ingest / subagents — they all funnel
//! through `drive_turn_stream`).
//!
//! The cloud heartbeat reads this so a closed-browser batch — no WS
//! clients, but the engine is still iterating tool calls — keeps
//! pinging `/keepalive` and the cloud reaper doesn't pause the pod
//! mid-batch.
//!
//! Process-global by design: there is exactly one engine process per
//! workspace; the heartbeat is per-process; the busy state is
//! per-process. Threading an `Arc<AtomicUsize>` through every
//! `WorkerState` construction path would be noisier than a static
//! and buy nothing.

use std::sync::atomic::{AtomicUsize, Ordering};

static AGENT_BUSY_COUNT: AtomicUsize = AtomicUsize::new(0);

/// RAII guard — increment on construction, decrement on drop. Use at
/// the top of any code path that should count as "agent doing work."
/// Drop runs on every return path, including panic-unwind, so this
/// stays correct around the many early `return`s in
/// `drive_turn_stream` (cancel, error, end-of-stream).
pub struct BusyGuard {
    _private: (),
}

impl BusyGuard {
    pub fn new() -> Self {
        AGENT_BUSY_COUNT.fetch_add(1, Ordering::SeqCst);
        Self { _private: () }
    }
}

impl Default for BusyGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for BusyGuard {
    fn drop(&mut self) {
        AGENT_BUSY_COUNT.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Is at least one agent turn currently in flight in this process?
pub fn is_agent_busy() -> bool {
    AGENT_BUSY_COUNT.load(Ordering::SeqCst) > 0
}

/// Current in-flight turn count. Mainly for tests + future
/// observability; the heartbeat just wants the boolean.
pub fn busy_count() -> usize {
    AGENT_BUSY_COUNT.load(Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_increments_and_decrements() {
        let baseline = busy_count();
        {
            let _g = BusyGuard::new();
            assert_eq!(busy_count(), baseline + 1);
            assert!(is_agent_busy());
        }
        assert_eq!(busy_count(), baseline);
    }

    #[test]
    fn nested_guards_stack() {
        let baseline = busy_count();
        let _outer = BusyGuard::new();
        {
            let _inner = BusyGuard::new();
            assert_eq!(busy_count(), baseline + 2);
        }
        assert_eq!(busy_count(), baseline + 1);
    }

    #[test]
    fn guard_survives_early_return() {
        fn maybe_work(do_work: bool) -> Option<()> {
            let _g = BusyGuard::new();
            if !do_work {
                return None;
            }
            Some(())
        }
        let baseline = busy_count();
        let _ = maybe_work(false);
        assert_eq!(busy_count(), baseline, "early return must drop guard");
        let _ = maybe_work(true);
        assert_eq!(busy_count(), baseline);
    }
}
