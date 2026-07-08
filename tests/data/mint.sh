#!/bin/bash
# Mint FAT12/FAT16/FAT32/exFAT oracle images with known files (macOS).
# Each image gets: a short-named file, a long-named (LFN) file, and a nested dir
# with a file. TSK (fls/istat/icat) is the independent oracle asserted in tests.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

mint_msdos() {
  local fatbits="$1" img="$2" sizemb="$3"
  rm -f "$img"
  # Raw zero-filled image
  dd if=/dev/zero of="$img" bs=1m count="$sizemb" status=none
  # Attach as a raw disk, no mount
  local dev
  dev="$(hdiutil attach -nomount -imagekey diskimage-class=CRawDiskImage "$img" | awk 'NR==1{print $1}')"
  echo "attached $img -> $dev"
  # Format FAT with requested bit width; 512-byte sectors
  newfs_msdos -F "$fatbits" -v FAT"$fatbits" "$dev" >/dev/null
  # Mount to write files
  diskutil mount "$dev" >/dev/null
  local vol="/Volumes/FAT$fatbits"
  printf 'hello from FAT%s\n' "$fatbits" > "$vol/HELLO.TXT"
  printf 'this file has a long name for LFN reassembly test\n' > "$vol/LongFileName_${fatbits}.txt"
  mkdir -p "$vol/subdir"
  printf 'nested file content %s\n' "$fatbits" > "$vol/subdir/NESTED.TXT"
  sync
  diskutil unmount "$dev" >/dev/null
  hdiutil detach "$dev" >/dev/null
  echo "minted $img"
}

mint_exfat() {
  local img="$1" sizemb="$2"
  rm -f "$img"
  dd if=/dev/zero of="$img" bs=1m count="$sizemb" status=none
  local dev
  dev="$(hdiutil attach -nomount -imagekey diskimage-class=CRawDiskImage "$img" | awk 'NR==1{print $1}')"
  echo "attached $img -> $dev"
  newfs_exfat -v EXFATVOL "$dev" >/dev/null
  diskutil mount "$dev" >/dev/null
  local vol="/Volumes/EXFATVOL"
  printf 'hello from exFAT\n' > "$vol/HELLO.TXT"
  printf 'this exFAT file has a long name stored in File Name entries\n' > "$vol/LongFileName_exfat.txt"
  mkdir -p "$vol/subdir"
  printf 'nested exfat content\n' > "$vol/subdir/NESTED.TXT"
  sync
  diskutil unmount "$dev" >/dev/null
  hdiutil detach "$dev" >/dev/null
  echo "minted $img"
}

mint_msdos 12 fat12.img 2
mint_msdos 16 fat16.img 48
mint_msdos 32 fat32.img 64
mint_exfat exfat.img 48

echo "=== md5 ==="
md5 fat12.img fat16.img fat32.img exfat.img
