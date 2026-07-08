//! fat4n6 — debug CLI for fat-core / fat-forensic.

fn main() {
    println!("fat4n6 {}", env!("CARGO_PKG_VERSION"));
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
        assert!(out.contains("FAT12"));
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
