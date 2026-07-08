//! Analyzer tests. Clean minted images must produce no structural false
//! positives; targeted mutations of a real image (the mutation *is* the ground
//! truth) must be detected.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use fat::FatFs;
use fat_forensic::audit_reader;

fn has_code(anoms: &[fat_forensic::Anomaly], code: &str) -> bool {
    anoms.iter().any(|a| a.code == code)
}

#[test]
fn clean_fat16_has_no_structural_anomalies() {
    let img = include_bytes!("../../tests/data/fat16.img").to_vec();
    let anoms = audit_reader(Cursor::new(img)).unwrap();
    assert!(!has_code(&anoms, "FAT-MIRROR-MISMATCH"));
    assert!(!has_code(&anoms, "FAT-BOOT-SIG-INVALID"));
    assert!(!has_code(&anoms, "FAT-BPB-INVALID"));
}

#[test]
fn clean_exfat_checksum_matches() {
    let img = include_bytes!("../../tests/data/exfat.img").to_vec();
    let anoms = audit_reader(Cursor::new(img)).unwrap();
    assert!(!has_code(&anoms, "EXFAT-BOOT-CHECKSUM-MISMATCH"));
}

#[test]
fn detects_bad_boot_signature() {
    let mut img = include_bytes!("../../tests/data/fat12.img").to_vec();
    img[510] = 0x00;
    img[511] = 0x00;
    let anoms = audit_reader(Cursor::new(img)).unwrap();
    assert!(has_code(&anoms, "FAT-BOOT-SIG-INVALID"));
}

#[test]
fn detects_invalid_bpb() {
    // Valid 0x55AA signature but a structurally impossible BPB.
    let mut img = vec![0u8; 2048];
    img[510] = 0x55;
    img[511] = 0xAA;
    let anoms = audit_reader(Cursor::new(img)).unwrap();
    assert!(has_code(&anoms, "FAT-BPB-INVALID"));
}

#[test]
fn detects_fat_mirror_mismatch() {
    let base = include_bytes!("../../tests/data/fat16.img").to_vec();
    let geom = FatFs::open(Cursor::new(base.clone()))
        .unwrap()
        .geometry()
        .clone();
    let fat2 = (geom.fat_start
        + u64::from(geom.fat_size_sectors) * u64::from(geom.bytes_per_sector))
        as usize;
    let mut img = base;
    img[fat2 + 8] ^= 0xFF; // corrupt one FAT2 byte
    let anoms = audit_reader(Cursor::new(img)).unwrap();
    assert!(has_code(&anoms, "FAT-MIRROR-MISMATCH"));
}

#[test]
fn detects_exfat_boot_checksum_mismatch() {
    let mut img = include_bytes!("../../tests/data/exfat.img").to_vec();
    // VolumeSerialNumber (offset 100): checksummed, not excluded (106/107/112),
    // outside the EXFAT signature, and not a field the parser validates.
    img[100] ^= 0xFF;
    let anoms = audit_reader(Cursor::new(img)).unwrap();
    assert!(has_code(&anoms, "EXFAT-BOOT-CHECKSUM-MISMATCH"));
}

#[test]
fn surfaces_a_deleted_directory_entry() {
    let mut img = include_bytes!("../../tests/data/fat12.img").to_vec();
    // Delete HELLO.TXT by overwriting its short-entry first byte with 0xE5.
    let pos = img
        .windows(11)
        .position(|w| w == b"HELLO   TXT")
        .expect("HELLO.TXT entry present");
    img[pos] = 0xE5;
    let anoms = audit_reader(Cursor::new(img)).unwrap();
    assert!(has_code(&anoms, "FAT-DIR-ENTRY-DELETED"));
}

#[test]
fn anomaly_is_a_graded_observation() {
    use forensicnomicon::report::{Observation, Severity};
    let mut img = include_bytes!("../../tests/data/fat12.img").to_vec();
    img[510] = 0x00;
    let anoms = audit_reader(Cursor::new(img)).unwrap();
    let sig = anoms
        .iter()
        .find(|a| a.code == "FAT-BOOT-SIG-INVALID")
        .unwrap();
    assert_eq!(Observation::severity(sig), Some(Severity::High));
    assert!(!Observation::note(sig).is_empty());
    assert!(!Observation::evidence(sig).is_empty()); // carries the offending value
}
