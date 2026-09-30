//! Deterministic fault-injection seams and test-only ownership/recovery overrides.
//!
//! Faults and fake ownership/recovery locations exist only in the unit-test binary.

use std::io;
#[cfg(test)]
use std::{collections::BTreeMap, path::PathBuf};

#[cfg(test)]
#[derive(Default)]
pub(crate) struct TestHooks {
    pub(crate) faults: BTreeMap<&'static str, usize>,
    pub(crate) owner_dest: Option<PathBuf>,
    pub(crate) owner: Option<String>,
    pub(crate) recovery: Option<PathBuf>,
}

#[cfg(test)]
thread_local! {
    pub(crate) static TEST_HOOKS: std::cell::RefCell<TestHooks> = std::cell::RefCell::new(TestHooks::default());
}

#[cfg_attr(
    not(test),
    expect(
        clippy::unnecessary_wraps,
        reason = "fault-injection seam: only the unit-test build injects failures"
    )
)]
pub(crate) fn fault(point: &str) -> io::Result<()> {
    #[cfg(test)]
    return TEST_HOOKS.with(|hooks| {
        let mut hooks = hooks.borrow_mut();
        if let Some(count) = hooks.faults.get_mut(point) {
            if *count > 0 {
                *count -= 1;
            } else {
                hooks.faults.remove(point);
                return Err(io::Error::other(format!("injected {point} failure")));
            }
        }
        Ok(())
    });
    #[cfg(not(test))]
    {
        let _ = point;
        Ok(())
    }
}
