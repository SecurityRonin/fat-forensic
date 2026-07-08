//! fat4n6 — a debug CLI over fat-core / fat-forensic: list a FAT/exFAT volume's
//! tree and audit it for anomalies. The fleet end-user CLI is issen/disk4n6.
//!
//! All decision logic lives in the testable [`run_args`]; `main` is an
//! irreducible shell (Humble Object).

use std::io::Write;
use std::path::Path;

use fat::{FatFs, FileId};

fn main() {
    let args: Vec<String> = std::env::args().collect(); // cov:unreachable: shell
    let code = run_args(&args, &mut std::io::stdout()); // cov:unreachable: shell
    std::process::exit(code); // cov:unreachable: shell
}

/// Parse `args` and dispatch, writing all output to `out`. Returns the process
/// exit code (0 ok, 1 open/read error, 2 usage error).
pub fn run_args<W: Write>(args: &[String], out: &mut W) -> i32 {
    if args.iter().any(|a| a == "-V" || a == "--version") {
        let _ = writeln!(out, "fat4n6 {}", env!("CARGO_PKG_VERSION"));
        return 0;
    }
    let Some(path) = args.get(1) else {
        let _ = writeln!(out, "usage: fat4n6 [-V|--version] <image>");
        return 2;
    };
    run(Path::new(path), out)
}

/// List the volume tree and audit it.
fn run<W: Write>(path: &Path, out: &mut W) -> i32 {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => {
            let _ = writeln!(out, "error: cannot open {}: {e}", path.display());
            return 1;
        }
    };
    let fs = match FatFs::open(file) {
        Ok(f) => f,
        Err(e) => {
            let _ = writeln!(out, "error: not a FAT/exFAT volume: {e}");
            return 1;
        }
    };

    let _ = writeln!(out, "variant: {:?}", fs.variant());
    let _ = writeln!(out, "files:");
    list(&fs, fs.root(), 0, out);

    let _ = writeln!(out, "anomalies:");
    match fat_forensic::audit_path(path) {
        Ok(anoms) if anoms.is_empty() => {
            let _ = writeln!(out, "  (none)");
        }
        Ok(anoms) => {
            for a in anoms {
                let _ = writeln!(out, "  [{:?}] {}: {}", a.severity, a.code, a.note);
            }
        }
        Err(e) => {
            let _ = writeln!(out, "  audit error: {e}");
        }
    }
    0
}

/// Recursively print the directory tree (indented), skipping `.`/`..` and
/// bounding depth.
fn list<W: Write, R: std::io::Read + std::io::Seek>(
    fs: &FatFs<R>,
    dir: FileId,
    depth: usize,
    out: &mut W,
) {
    if depth >= 64 {
        return; // cov:unreachable: real FAT trees are far shallower than 64
    }
    let Ok(nodes) = fs.read_dir(dir) else {
        return;
    };
    for node in nodes {
        if node.name == "." || node.name == ".." || node.is_volume_label {
            continue;
        }
        let indent = "  ".repeat(depth + 1);
        let mark = if node.is_deleted { " (deleted)" } else { "" };
        if node.is_dir {
            let _ = writeln!(out, "{indent}{}/{mark}", node.name);
            if !node.is_deleted {
                list(fs, node.id, depth + 1, out);
            }
        } else {
            let _ = writeln!(out, "{indent}{} ({} bytes){mark}", node.name, node.size);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::run_args;

    fn image(name: &str) -> String {
        format!("{}/../tests/data/{name}", env!("CARGO_MANIFEST_DIR"))
    }

    fn run(args: &[&str]) -> (i32, String) {
        let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        let mut buf = Vec::new();
        let code = run_args(&owned, &mut buf);
        (code, String::from_utf8(buf).unwrap())
    }

    #[test]
    fn version_flag() {
        let (code, out) = run(&["fat4n6", "--version"]);
        assert_eq!(code, 0);
        assert!(out.contains("fat4n6 "));
        assert_eq!(run(&["fat4n6", "-V"]).0, 0);
    }

    #[test]
    fn missing_argument_is_usage_error() {
        let (code, out) = run(&["fat4n6"]);
        assert_eq!(code, 2);
        assert!(out.contains("usage"));
    }

    #[test]
    fn nonexistent_image_errors() {
        let (code, out) = run(&["fat4n6", "/no/such/image.img"]);
        assert_eq!(code, 1);
        assert!(out.contains("error"));
    }

    #[test]
    fn non_fat_image_errors() {
        let path = format!("{}/src/main.rs", env!("CARGO_MANIFEST_DIR"));
        let (code, out) = run(&["fat4n6", &path]);
        assert_eq!(code, 1);
        assert!(out.contains("not a FAT"));
    }

    #[test]
    fn lists_and_audits_fat12() {
        let (code, out) = run(&["fat4n6", &image("fat12.img")]);
        assert_eq!(code, 0);
        assert!(out.contains("Fat12"));
        assert!(out.contains("HELLO.TXT"));
        assert!(out.contains("subdir/"));
        assert!(out.contains("NESTED.TXT"));
        assert!(out.contains("anomalies:"));
    }

    #[test]
    fn lists_exfat() {
        let (code, out) = run(&["fat4n6", &image("exfat.img")]);
        assert_eq!(code, 0);
        assert!(out.contains("ExFat"));
        assert!(out.contains("HELLO.TXT"));
    }
}
