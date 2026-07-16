# Changelog

All notable changes to `fat-core` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1]

### Changed

- Migrate to forensic-vfs 0.3 (FsKind newtype). The `vfs` feature's
  `FileSystem` adapter now returns the `FsKind::FAT` / `FsKind::EXFAT`
  associated consts of the `FsKind` newtype instead of the old
  `FsKind::Fat` / `FsKind::ExFat` enum variants.

## [0.1.0]

- Initial release: pure-Rust, panic-free forensic reader for FAT12/16/32 and
  exFAT with an optional forensic-vfs `FileSystem` adapter.
