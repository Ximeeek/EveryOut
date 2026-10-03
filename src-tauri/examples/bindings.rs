fn main() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../src/api/types.ts");
    let expected = everyout_lib::bindings::typescript();
    if std::env::args().any(|arg| arg == "--check") {
        assert_eq!(
            std::fs::read_to_string(path)
                .expect("committed IPC types")
                .replace("\r\n", "\n"),
            expected,
            "IPC types are stale; run pnpm bindings:generate"
        );
    } else {
        std::fs::create_dir_all(path.parent().expect("api directory")).expect("api directory");
        std::fs::write(path, expected).expect("IPC types");
    }
}
