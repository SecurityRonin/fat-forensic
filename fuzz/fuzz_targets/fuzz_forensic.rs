#![no_main]
//! The full FAT/exFAT forensic audit pipeline over arbitrary bytes — must never panic.
use std::io::Cursor;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = fat_forensic::audit_reader(Cursor::new(data));
});
