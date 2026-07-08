#![no_main]
//! FAT cluster-chain following must never panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fat::__fuzz::walk_fat_chain(data);
});
