//! Debug output, shown only when the resolver runs with -v / --verbose.

use std::sync::atomic::{AtomicBool, Ordering};

static VERBOSE: AtomicBool = AtomicBool::new(false);

pub fn set_verbose(on: bool) {
    VERBOSE.store(on, Ordering::Relaxed);
}

pub fn is_verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

/// `println!` that prints only in verbose mode.
macro_rules! debug {
    ($($arg:tt)*) => {
        if $crate::log::is_verbose() {
            println!($($arg)*);
        }
    };
}
