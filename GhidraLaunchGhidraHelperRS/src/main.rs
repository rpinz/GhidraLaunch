//! Native Ghidra payload extraction/removal helper used by the Ghidra Launch installers.

mod archive;
mod cli;
mod extract;
mod fs_safety;
mod hooks;
mod migration;
mod registry;
mod remove;
mod state;
#[cfg(test)]
mod test_support;

use std::env;
use std::ffi::OsString;

fn main() {
    // A process can be started with an empty command line, so argv[0] may be absent.
    let arguments: Vec<OsString> = env::args_os().skip(1).collect();
    std::process::exit(cli::exit_code(&arguments));
}
