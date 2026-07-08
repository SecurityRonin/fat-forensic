#![no_main]
//! FAT12/16/32 BPB parse must never panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fat::__fuzz::parse_bpb(data);
});
