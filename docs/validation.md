# Validation

`fat-core`'s reader is a **value-producing, oracle-feasible** parser, so its
correctness is proven against an **independent oracle** — The Sleuth Kit (TSK) —
not only against fixtures we authored. Validation tier is **tier-2**: the images
are self-minted (we chose the scenario), but the ground truth is derived by an
independent third-party tool, not by us.

## Method

`tests/data/mint.sh` mints one image of each variant on a macOS host with the OS
formatters (`newfs_msdos -F 12/16/32`, `newfs_exfat`) and writes three known
artifacts to each: a short 8.3 name (`HELLO.TXT`), a long name exercising VFAT /
exFAT name reassembly (`LongFileName_<variant>.txt`), and a file inside a nested
directory (`subdir/NESTED.TXT`). macOS additionally writes a `.fseventsd/`
directory and a volume-label entry — real-world quirks the reader must tolerate.

For every artifact, the integration tests assert that `fat-core` independently
reproduces the **name, size and first content bytes** that TSK reports via
`fls` / `istat` / `icat`:

| Image | File | Size (bytes) | First content bytes |
|---|---|---|---|
| fat12/16/32 | `HELLO.TXT` | 17 | `hello from FAT<bits>` |
| fat12/16/32 | `LongFileName_<bits>.txt` | 50 | `this file has a long name for LFN reassembly test` |
| fat12/16/32 | `subdir/NESTED.TXT` | 23 | `nested file content <bits>` |
| exfat | `HELLO.TXT` | 17 | `hello from exFAT` |
| exfat | `LongFileName_exfat.txt` | 59 | `this exFAT file has a long name stored in File Name entries` |
| exfat | `subdir/NESTED.TXT` | 21 | `nested exfat content` |

The FAT12/16/exFAT images are small and committed; the FAT32 image is 34 MiB
(FAT32 requires ≥65525 clusters) and is regenerated via `mint.sh`, with its test
env-gated on `FAT_FORENSIC_FAT32_IMG`.

## Robustness

Every parsed structure has a `cargo-fuzz` target (`bpb`, `fat_chain`,
`dir_entry`, `exfat_boot`, `exfat_dir`) plus `fuzz_forensic` over the audit
pipeline; the invariant is "must not panic". Coverage is gated at 100% of
executable library lines, with `// cov:unreachable` reserved for provably-dead
defensive arms.
