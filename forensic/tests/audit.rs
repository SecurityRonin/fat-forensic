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
fn audit_path_opens_a_real_file() {
    let path = format!("{}/../tests/data/fat16.img", env!("CARGO_MANIFEST_DIR"));
    let anoms = fat_forensic::audit_path(std::path::Path::new(&path)).unwrap();
    assert!(!has_code(&anoms, "FAT-BOOT-SIG-INVALID"));
    // A missing file is a loud error, not an empty result.
    assert!(fat_forensic::audit_path(std::path::Path::new("/no/such/img")).is_err());
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
fn single_fat_volume_skips_the_mirror_check() {
    // A valid non-exFAT volume with num_fats == 1 (BPB 0x10): there is no
    // second FAT to compare, so neither audit branch runs and no mirror
    // anomaly is raised. Exercises the if/else-if fall-through.
    let mut img = include_bytes!("../../tests/data/fat16.img").to_vec();
    img[16] = 1; // num FATs: 2 -> 1
    let anoms = audit_reader(Cursor::new(img)).unwrap();
    assert!(!has_code(&anoms, "FAT-MIRROR-MISMATCH"));
    assert!(!has_code(&anoms, "FAT-BPB-INVALID"));
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
fn truncated_exfat_does_not_false_positive_checksum() {
    // Cut the image below the 12-sector boot region: the checksum cannot be
    // verified, and the auditor must not fabricate a mismatch.
    let full = include_bytes!("../../tests/data/exfat.img").to_vec();
    let img = full[..3000].to_vec();
    let anoms = audit_reader(Cursor::new(img)).unwrap();
    assert!(!has_code(&anoms, "EXFAT-BOOT-CHECKSUM-MISMATCH"));
}

#[test]
fn truncated_fat_regions_skip_mirror_check() {
    let base = include_bytes!("../../tests/data/fat16.img").to_vec();
    let geom = FatFs::open(Cursor::new(base.clone()))
        .unwrap()
        .geometry()
        .clone();
    let fat_bytes = (u64::from(geom.fat_size_sectors) * u64::from(geom.bytes_per_sector)) as usize;
    let fat_start = geom.fat_start as usize;

    // FAT1 truncated mid-region → cannot compare, no anomaly, no panic.
    let img1 = base[..fat_start + fat_bytes / 2].to_vec();
    assert!(!has_code(
        &audit_reader(Cursor::new(img1)).unwrap(),
        "FAT-MIRROR-MISMATCH"
    ));

    // FAT1 complete but FAT2 truncated mid-region.
    let img2 = base[..fat_start + fat_bytes + fat_bytes / 2].to_vec();
    assert!(!has_code(
        &audit_reader(Cursor::new(img2)).unwrap(),
        "FAT-MIRROR-MISMATCH"
    ));
}

#[test]
fn read_error_during_fat_read_surfaces_loud() {
    // Serves the boot sector, then fails on the FAT read.
    struct FailAfterBoot {
        img: Vec<u8>,
        pos: u64,
        fail_at: u64,
    }
    impl std::io::Read for FailAfterBoot {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.pos >= self.fail_at {
                return Err(std::io::Error::other("blocked"));
            }
            let start = self.pos as usize;
            let n = buf.len().min(self.img.len().saturating_sub(start));
            buf[..n].copy_from_slice(&self.img[start..start + n]);
            self.pos += n as u64;
            Ok(n)
        }
    }
    impl std::io::Seek for FailAfterBoot {
        fn seek(&mut self, from: std::io::SeekFrom) -> std::io::Result<u64> {
            if let std::io::SeekFrom::Start(p) = from {
                self.pos = p;
            }
            Ok(self.pos)
        }
    }
    let base = include_bytes!("../../tests/data/fat16.img").to_vec();
    let geom = FatFs::open(Cursor::new(base.clone()))
        .unwrap()
        .geometry()
        .clone();
    let reader = FailAfterBoot {
        img: base,
        pos: 0,
        fail_at: geom.fat_start, // boot read succeeds; the FAT read errors
    };
    assert!(audit_reader(reader).is_err());
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
