#![no_main]
//! exFAT directory-entry-set decode must never panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fat::__fuzz::parse_exfat_dir(data);
});
