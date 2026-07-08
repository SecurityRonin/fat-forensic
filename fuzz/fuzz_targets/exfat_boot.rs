#![no_main]
//! exFAT boot-sector parse must never panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fat::__fuzz::parse_exfat_boot(data);
});
