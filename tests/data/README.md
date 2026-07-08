# Test data — FAT/exFAT oracle fixtures

All fixtures here are **self-minted** on a macOS host with the OS FAT/exFAT
formatters and validated against **The Sleuth Kit (TSK)** as an independent
oracle (`fls` / `istat` / `icat` / `fsstat`). Validation tier is **tier-2**
(self-minted scenario + independent third-party oracle), not tier-1.

Regenerate every image with the committed generator:

```
./mint.sh          # mints fat12.img, fat16.img, fat32.img, exfat.img
```

The generator writes, on each volume, three known artifacts:

- `HELLO.TXT` — a short 8.3 name
- `LongFileName_<variant>.txt` — a VFAT/exFAT long name (LFN reassembly test)
- `subdir/NESTED.TXT` — a file inside a nested directory

macOS additionally writes a `.fseventsd/` directory and a volume-label entry;
these are real-world quirks the reader must tolerate.

## TSK oracle ground truth (asserted by the integration tests)

| Image | File | Size (bytes) | First content bytes |
|---|---|---|---|
| fat12/16/32 | `HELLO.TXT` | 17 | `hello from FAT<bits>\n` |
| fat12/16/32 | `LongFileName_<bits>.txt` | 50 | `this file has a long name for LFN reassembly test\n` |
| fat12/16/32 | `subdir/NESTED.TXT` | 23 | `nested file content <bits>\n` |
| exfat | `HELLO.TXT` | 17 | `hello from exFAT\n` |
| exfat | `LongFileName_exfat.txt` | 59 | `this exFAT file has a long name stored in File Name entries\n` |
| exfat | `subdir/NESTED.TXT` | 21 | `nested exfat content\n` |

## Files

#### fat12.img
- **Source**: self-minted, `mint.sh` → `newfs_msdos -F 12 -c 1 -v FAT12 <dev>`
- **Size**: 2 MiB (2880 × 512-byte sectors, single-sector clusters → FAT12)
- **fsstat**: File System Type FAT12, cluster range 2–4040
- **Committed**: yes (small)

#### fat16.img
- **Source**: self-minted, `mint.sh` → `newfs_msdos -F 16 -c 1 -v FAT16 <dev>`
- **Size**: 4 MiB (single-sector clusters → ~8000 clusters → FAT16)
- **fsstat**: File System Type FAT16
- **Committed**: yes (small)

#### fat32.img
- **Source**: self-minted, `mint.sh` → `newfs_msdos -F 32 -c 1 -v FAT32 <dev>`
- **Size**: 34 MiB (≥65525 single-sector clusters required for FAT32)
- **fsstat**: File System Type FAT32, root at cluster 2
- **Committed**: **no** — gitignored (34 MiB). Regenerate via `mint.sh`; the
  integration test is env-gated on `FAT_FORENSIC_FAT32_IMG` (path to the image),
  and skips cleanly when unset.

#### exfat.img
- **Source**: self-minted, `mint.sh` → `newfs_exfat -v EXFATVOL <dev>`
- **Size**: 2 MiB, 4096-byte clusters
- **fsstat**: File System Type exFAT, volume label EXFATVOL
- **Committed**: yes (small)

Provenance is also indexed in the fleet catalog `issen/docs/corpus-catalog.md`.
