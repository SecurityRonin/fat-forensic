//! Tier-2 validation: `fat-core` independently reproduces the name, size and
//! first content bytes that **The Sleuth Kit** reports (via `fls`/`istat`/`icat`)
//! for every self-minted FAT12/16/32/exFAT image. The images and the TSK ground
//! truth are documented in `tests/data/README.md`.
//!
//! FAT12/16/exFAT images are committed and asserted unconditionally. The FAT32
//! image is 34 MiB (FAT32 needs ≥65525 clusters) and is gitignored; its test is
//! env-gated on `FAT_FORENSIC_FAT32_IMG` and skips cleanly when unset.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use fat::FatFs;

/// Assert the three known artifacts every minted image carries.
fn assert_known_files(img: &[u8], hello: &[u8], long_name: &str, long: &[u8], nested: &[u8]) {
    let fs = FatFs::open(Cursor::new(img)).expect("open");
    let root = fs.root();

    // HELLO.TXT — a short 8.3 name.
    let id = fs
        .lookup(root, b"HELLO.TXT")
        .unwrap()
        .expect("HELLO.TXT present");
    let meta = fs.meta(id).unwrap();
    assert_eq!(meta.size as usize, hello.len(), "HELLO.TXT size");
    assert!(meta.modified.is_some(), "HELLO.TXT has a modified time");
    let mut buf = vec![0u8; hello.len()];
    let n = fs.read_at(id, 0, &mut buf).unwrap();
    assert_eq!(&buf[..n], hello, "HELLO.TXT content");

    // Long name — VFAT / exFAT reassembly.
    let id = fs
        .lookup(root, long_name.as_bytes())
        .unwrap()
        .unwrap_or_else(|| panic!("{long_name} present"));
    let meta = fs.meta(id).unwrap();
    assert_eq!(meta.size as usize, long.len(), "long-name size");
    let mut buf = vec![0u8; long.len()];
    let n = fs.read_at(id, 0, &mut buf).unwrap();
    assert_eq!(&buf[..n], long, "long-name content");

    // subdir/NESTED.TXT — a file inside a nested directory.
    let sub = fs.lookup(root, b"subdir").unwrap().expect("subdir present");
    assert!(fs.meta(sub).unwrap().is_dir, "subdir is a directory");
    let id = fs
        .lookup(sub, b"NESTED.TXT")
        .unwrap()
        .expect("NESTED.TXT present");
    let meta = fs.meta(id).unwrap();
    assert_eq!(meta.size as usize, nested.len(), "NESTED.TXT size");
    let mut buf = vec![0u8; nested.len()];
    let n = fs.read_at(id, 0, &mut buf).unwrap();
    assert_eq!(&buf[..n], nested, "NESTED.TXT content");
}

#[test]
fn fat12_matches_tsk() {
    assert_known_files(
        include_bytes!("../../tests/data/fat12.img"),
        b"hello from FAT12\n",
        "LongFileName_12.txt",
        b"this file has a long name for LFN reassembly test\n",
        b"nested file content 12\n",
    );
}

#[test]
fn fat16_matches_tsk() {
    assert_known_files(
        include_bytes!("../../tests/data/fat16.img"),
        b"hello from FAT16\n",
        "LongFileName_16.txt",
        b"this file has a long name for LFN reassembly test\n",
        b"nested file content 16\n",
    );
}

#[test]
fn exfat_matches_tsk() {
    assert_known_files(
        include_bytes!("../../tests/data/exfat.img"),
        b"hello from exFAT\n",
        "LongFileName_exfat.txt",
        b"this exFAT file has a long name stored in File Name entries\n",
        b"nested exfat content\n",
    );
}

#[test]
fn fat32_matches_tsk() {
    let Ok(path) = std::env::var("FAT_FORENSIC_FAT32_IMG") else {
        eprintln!("skipping: FAT_FORENSIC_FAT32_IMG unset (regenerate via tests/data/mint.sh)");
        return;
    };
    let img = std::fs::read(path).expect("read fat32 image");
    assert_known_files(
        &img,
        b"hello from FAT32\n",
        "LongFileName_32.txt",
        b"this file has a long name for LFN reassembly test\n",
        b"nested file content 32\n",
    );
}
