#![no_main]
//! FAT 8.3/VFAT directory decode must never panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fat::__fuzz::parse_dir_entry(data);
});
