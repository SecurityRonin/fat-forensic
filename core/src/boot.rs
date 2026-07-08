//! FAT12/16/32 boot sector (BIOS Parameter Block) parse, geometry, and the
//! cluster-count FAT-type decision (fatgen103 §3.5): `< 4085` → FAT12,
//! `< 65525` → FAT16, else FAT32.

use crate::bytes::{le_u16, le_u32, u8_at};
use crate::error::{FatError, Result};

/// The FAT-type cutoffs from Microsoft's fatgen103 specification. These bounds
/// are the *definition* of the type, not a heuristic (spec §3.5).
const FAT12_MAX_CLUSTERS: u32 = 4085;
const FAT16_MAX_CLUSTERS: u32 = 65525;

/// Which member of the FAT family a volume is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FatVariant {
    /// 12-bit cluster indices.
    Fat12,
    /// 16-bit cluster indices.
    Fat16,
    /// 32-bit cluster indices.
    Fat32,
    /// exFAT (parsed by [`crate::exfat`], not the BPB path).
    ExFat,
}

/// Resolved on-disk geometry of a FAT12/16/32 volume. All byte offsets are
/// relative to the start of the volume (sector 0).
#[derive(Debug, Clone)]
pub struct Geometry {
    /// Which FAT variant.
    pub variant: FatVariant,
    /// Bytes per logical sector (power of two, 512–4096).
    pub bytes_per_sector: u32,
    /// Sectors per cluster (power of two, 1–128).
    pub sectors_per_cluster: u32,
    /// Cluster size in bytes.
    pub cluster_size: u32,
    /// Count of reserved sectors preceding the first FAT.
    pub reserved_sectors: u32,
    /// Number of FAT copies.
    pub num_fats: u32,
    /// Sectors occupied by one FAT.
    pub fat_size_sectors: u32,
    /// FAT12/16 fixed root directory entry count (0 on FAT32).
    pub root_entry_count: u32,
    /// Total sectors in the volume.
    pub total_sectors: u64,
    /// FAT32/exFAT first cluster of the root directory (0 on FAT12/16).
    pub root_cluster: u32,
    /// Count of data clusters (drives the type decision).
    pub count_of_clusters: u32,
    /// Byte offset of the first FAT.
    pub fat_start: u64,
    /// Byte offset of the FAT12/16 fixed root region (0 on FAT32).
    pub root_dir_start: u64,
    /// Byte size of the FAT12/16 fixed root region (0 on FAT32).
    pub root_dir_bytes: u32,
    /// Byte offset of cluster 2 (start of the data region).
    pub data_start: u64,
}

/// The validated raw BPB fields, before offsets and the type decision.
struct Fields {
    bytes_per_sector: u32,
    sectors_per_cluster: u32,
    reserved_sectors: u32,
    num_fats: u32,
    root_entry_count: u32,
    fat_size_sectors: u32,
    total_sectors: u64,
}

impl Geometry {
    /// Parse the BPB from the boot sector `boot` (at least 512 bytes).
    ///
    /// Fails loud, naming the offending value, on any structurally invalid
    /// field — an invalid BPB is a bootstrap failure, never a silent default.
    pub fn parse(boot: &[u8]) -> Result<Geometry> {
        let f = read_fields(boot)?;
        let bps = u64::from(f.bytes_per_sector);

        // root_dir_sectors = ceil(root_entry_count * 32 / bytes_per_sector).
        let root_dir_sectors = (u64::from(f.root_entry_count) * 32).div_ceil(bps);
        let meta_sectors = u64::from(f.reserved_sectors)
            + u64::from(f.num_fats) * u64::from(f.fat_size_sectors)
            + root_dir_sectors;
        if meta_sectors > f.total_sectors {
            return Err(FatError::InvalidBoot(format!(
                "reserved+FATs+root ({meta_sectors} sectors) exceeds total ({})",
                f.total_sectors
            )));
        }

        let data_sectors = f.total_sectors - meta_sectors;
        let count_of_clusters =
            u32::try_from(data_sectors / u64::from(f.sectors_per_cluster)).unwrap_or(u32::MAX);
        let variant = if count_of_clusters < FAT12_MAX_CLUSTERS {
            FatVariant::Fat12
        } else if count_of_clusters < FAT16_MAX_CLUSTERS {
            FatVariant::Fat16
        } else {
            FatVariant::Fat32
        };
        let is32 = variant == FatVariant::Fat32;

        let fat_start = u64::from(f.reserved_sectors) * bps;
        let root_region_start = (u64::from(f.reserved_sectors)
            + u64::from(f.num_fats) * u64::from(f.fat_size_sectors))
            * bps;
        let (root_dir_start, root_dir_bytes) = if is32 {
            (0, 0)
        } else {
            (
                root_region_start,
                u32::try_from(root_dir_sectors * bps).unwrap_or(u32::MAX),
            )
        };

        Ok(Geometry {
            variant,
            bytes_per_sector: f.bytes_per_sector,
            sectors_per_cluster: f.sectors_per_cluster,
            cluster_size: f.bytes_per_sector * f.sectors_per_cluster,
            reserved_sectors: f.reserved_sectors,
            num_fats: f.num_fats,
            fat_size_sectors: f.fat_size_sectors,
            root_entry_count: if is32 { 0 } else { f.root_entry_count },
            total_sectors: f.total_sectors,
            root_cluster: if is32 { le_u32(boot, 44) } else { 0 },
            count_of_clusters,
            fat_start,
            root_dir_start,
            root_dir_bytes,
            data_start: meta_sectors * bps,
        })
    }

    /// Byte offset of the first sector of `cluster` (>= 2) in the data region.
    pub fn cluster_offset(&self, cluster: u32) -> Option<u64> {
        if cluster < 2 {
            return None;
        }
        let rel = u64::from(cluster - 2).checked_mul(u64::from(self.cluster_size))?;
        self.data_start.checked_add(rel)
    }
}

/// Read and range-check the BPB fields, failing loud with the offending value.
fn read_fields(boot: &[u8]) -> Result<Fields> {
    let sig = le_u16(boot, 510);
    if sig != 0xAA55 {
        return Err(FatError::InvalidBoot(format!(
            "boot signature at 0x1FE is {sig:#06x}, expected 0x55AA"
        )));
    }

    let bytes_per_sector = u32::from(le_u16(boot, 11));
    if !bytes_per_sector.is_power_of_two() || !(512..=4096).contains(&bytes_per_sector) {
        return Err(FatError::InvalidBoot(format!(
            "bytes-per-sector at 0x0B is {bytes_per_sector}, not a power of two in 512..=4096"
        )));
    }

    let sectors_per_cluster = u32::from(u8_at(boot, 13));
    if !sectors_per_cluster.is_power_of_two() || !(1..=128).contains(&sectors_per_cluster) {
        return Err(FatError::InvalidBoot(format!(
            "sectors-per-cluster at 0x0D is {sectors_per_cluster}, not a power of two in 1..=128"
        )));
    }

    let reserved_sectors = u32::from(le_u16(boot, 14));
    if reserved_sectors == 0 {
        return Err(FatError::InvalidBoot(
            "reserved-sector count at 0x0E is 0".into(),
        ));
    }

    let num_fats = u32::from(u8_at(boot, 16));
    if num_fats == 0 {
        return Err(FatError::InvalidBoot("number of FATs at 0x10 is 0".into()));
    }

    let fat_size_16 = u32::from(le_u16(boot, 22));
    let fat_size_sectors = if fat_size_16 != 0 {
        fat_size_16
    } else {
        le_u32(boot, 36)
    };
    if fat_size_sectors == 0 {
        return Err(FatError::InvalidBoot(
            "FAT size is 0 (both 0x16 and 0x24 are zero)".into(),
        ));
    }

    let total_sectors_16 = u32::from(le_u16(boot, 19));
    let total_sectors = if total_sectors_16 != 0 {
        u64::from(total_sectors_16)
    } else {
        u64::from(le_u32(boot, 32))
    };
    if total_sectors == 0 {
        return Err(FatError::InvalidBoot(
            "total sector count is 0 (both 0x13 and 0x20 are zero)".into(),
        ));
    }

    Ok(Fields {
        bytes_per_sector,
        sectors_per_cluster,
        reserved_sectors,
        num_fats,
        root_entry_count: u32::from(le_u16(boot, 17)),
        fat_size_sectors,
        total_sectors,
    })
}

#[cfg(test)]
mod tests {
    use super::{FatVariant, Geometry};

    /// A classic 1.44 MiB floppy BPB: 512 B/sector, 1 sector/cluster,
    /// 1 reserved, 2 FATs of 9 sectors, 224 root entries, 2880 total sectors.
    fn fat12_boot() -> Vec<u8> {
        let mut b = vec![0u8; 512];
        b[0] = 0xEB;
        b[1] = 0x3C;
        b[2] = 0x90;
        b[11..13].copy_from_slice(&512u16.to_le_bytes()); // bytes/sector
        b[13] = 1; // sectors/cluster
        b[14..16].copy_from_slice(&1u16.to_le_bytes()); // reserved
        b[16] = 2; // num FATs
        b[17..19].copy_from_slice(&224u16.to_le_bytes()); // root entries
        b[19..21].copy_from_slice(&2880u16.to_le_bytes()); // total sectors 16
        b[22..24].copy_from_slice(&9u16.to_le_bytes()); // FAT size 16
        b[510] = 0x55;
        b[511] = 0xAA;
        b
    }

    /// A minimal FAT32 BPB: 512 B/sector, 1 sector/cluster, 32 reserved,
    /// 2 FATs of 512 sectors, 0 root entries, root cluster 2, 70000 sectors.
    fn fat32_boot() -> Vec<u8> {
        let mut b = vec![0u8; 512];
        b[0] = 0xEB;
        b[2] = 0x90;
        b[11..13].copy_from_slice(&512u16.to_le_bytes());
        b[13] = 1;
        b[14..16].copy_from_slice(&32u16.to_le_bytes());
        b[16] = 2;
        b[17..19].copy_from_slice(&0u16.to_le_bytes());
        b[19..21].copy_from_slice(&0u16.to_le_bytes()); // total16 = 0 → use total32
        b[22..24].copy_from_slice(&0u16.to_le_bytes()); // fat16 = 0 → use fat32
        b[32..36].copy_from_slice(&70000u32.to_le_bytes()); // total sectors 32
        b[36..40].copy_from_slice(&512u32.to_le_bytes()); // FAT size 32
        b[44..48].copy_from_slice(&2u32.to_le_bytes()); // root cluster
        b[510] = 0x55;
        b[511] = 0xAA;
        b
    }

    #[test]
    fn detects_fat12_geometry() {
        let g = Geometry::parse(&fat12_boot()).unwrap();
        assert_eq!(g.variant, FatVariant::Fat12);
        assert_eq!(g.bytes_per_sector, 512);
        assert_eq!(g.sectors_per_cluster, 1);
        assert_eq!(g.cluster_size, 512);
        // root_dir_sectors = (224*32+511)/512 = 14; data = 2880-(1+18+14)=2847
        assert_eq!(g.count_of_clusters, 2847);
        assert_eq!(g.fat_start, 512);
        assert_eq!(g.root_dir_start, 19 * 512);
        assert_eq!(g.root_dir_bytes, 14 * 512);
        assert_eq!(g.data_start, 33 * 512);
    }

    #[test]
    fn detects_fat32_geometry() {
        let g = Geometry::parse(&fat32_boot()).unwrap();
        assert_eq!(g.variant, FatVariant::Fat32);
        assert_eq!(g.root_entry_count, 0);
        assert_eq!(g.root_cluster, 2);
        assert_eq!(g.root_dir_bytes, 0);
        // data = 70000 - (32 + 2*512 + 0) = 68944 clusters (>= 65525 → FAT32)
        assert_eq!(g.count_of_clusters, 68944);
        assert_eq!(g.data_start, (32 + 1024) * 512);
    }

    #[test]
    fn detects_fat16_boundary() {
        // 5000 clusters → FAT16 (>= 4085, < 65525)
        let mut b = fat12_boot();
        b[17..19].copy_from_slice(&0u16.to_le_bytes()); // no root region for simplicity
        b[19..21].copy_from_slice(&0u16.to_le_bytes());
        b[32..36].copy_from_slice(&5033u32.to_le_bytes()); // total32
        b[22..24].copy_from_slice(&0u16.to_le_bytes());
        b[36..40].copy_from_slice(&16u32.to_le_bytes()); // fat32 slot as fat_size fallback
                                                         // total = 5033, reserved 1, 2 FATs*16 = 32, root 0 → data 5000 → FAT16
        let g = Geometry::parse(&b).unwrap();
        assert_eq!(g.variant, FatVariant::Fat16);
        assert_eq!(g.count_of_clusters, 5000);
    }

    #[test]
    fn cluster_offset_maps_from_data_start() {
        let g = Geometry::parse(&fat12_boot()).unwrap();
        // cluster 2 is the first data cluster → data_start.
        assert_eq!(g.cluster_offset(2), Some(g.data_start));
        // cluster 3 is one cluster further in.
        assert_eq!(
            g.cluster_offset(3),
            Some(g.data_start + u64::from(g.cluster_size))
        );
        // clusters 0 and 1 are reserved, not addressable.
        assert_eq!(g.cluster_offset(0), None);
        assert_eq!(g.cluster_offset(1), None);
    }

    #[test]
    fn rejects_bad_signature() {
        let mut b = fat12_boot();
        b[510] = 0x00;
        let e = Geometry::parse(&b).unwrap_err();
        assert!(format!("{e}").contains("55")); // reports the offending signature
    }

    #[test]
    fn rejects_non_power_of_two_sector() {
        let mut b = fat12_boot();
        b[11..13].copy_from_slice(&513u16.to_le_bytes());
        assert!(Geometry::parse(&b).is_err());
    }

    #[test]
    fn rejects_zero_fats() {
        let mut b = fat12_boot();
        b[16] = 0;
        assert!(Geometry::parse(&b).is_err());
    }

    #[test]
    fn rejects_non_power_of_two_cluster() {
        let mut b = fat12_boot();
        b[13] = 3; // sectors-per-cluster not a power of two
        assert!(Geometry::parse(&b).is_err());
    }

    #[test]
    fn rejects_zero_reserved() {
        let mut b = fat12_boot();
        b[14..16].copy_from_slice(&0u16.to_le_bytes());
        assert!(Geometry::parse(&b).is_err());
    }

    #[test]
    fn rejects_zero_fat_size() {
        let mut b = fat12_boot();
        b[22..24].copy_from_slice(&0u16.to_le_bytes()); // fat16=0
        b[36..40].copy_from_slice(&0u32.to_le_bytes()); // fat32=0
        assert!(Geometry::parse(&b).is_err());
    }

    #[test]
    fn rejects_zero_total_sectors() {
        let mut b = fat12_boot();
        b[19..21].copy_from_slice(&0u16.to_le_bytes()); // total16=0
        b[32..36].copy_from_slice(&0u32.to_le_bytes()); // total32=0
        assert!(Geometry::parse(&b).is_err());
    }

    #[test]
    fn rejects_oversize_reserved_region() {
        // reserved region larger than the volume → data underflow, must fail loud
        let mut b = fat12_boot();
        b[14..16].copy_from_slice(&9000u16.to_le_bytes());
        assert!(Geometry::parse(&b).is_err());
    }
}
