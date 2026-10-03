use std::{
    env, fs,
    path::{Path, PathBuf},
};
fn catalog(path: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(path).expect("bundled catalog") {
        let path = entry.expect("catalog entry").path();
        if path.is_dir() {
            catalog(&path, files);
        } else if path.extension().is_some_and(|e| e == "json") {
            files.push(path.canonicalize().expect("catalog path"));
        }
    }
}
fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("out dir"));
    println!("cargo:rerun-if-env-changed=EVERYOUT_HELPER_SHA256");
    let pin = env::var("EVERYOUT_HELPER_SHA256").ok().map(|value| {
        assert!(
            value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()),
            "EVERYOUT_HELPER_SHA256 must be a build-provided SHA-256 pin"
        );
        (0..32)
            .map(|i| u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).expect("hex pin"))
            .collect::<Vec<_>>()
    });
    fs::write(
        out.join("helper_pin.rs"),
        format!(
            "const HELPER_PIN: Option<[u8;32]> = {};\n",
            pin.map(|p| format!("Some({p:?})"))
                .unwrap_or_else(|| "None".into())
        ),
    )
    .expect("helper pin");
    let mut files = Vec::new();
    for dir in ["browsers", "apps", "windows-dev"] {
        let path = Path::new("../catalog").join(dir);
        println!("cargo:rerun-if-changed={}", path.display());
        catalog(&path, &mut files);
    }
    files.sort();
    let mut code = String::from("const BUNDLED: &[&str] = &[\n");
    for file in files {
        code.push_str(&format!(
            "include_str!({:?}),\n",
            file.to_str().expect("catalog path")
        ));
    }
    code.push_str("];\n");
    fs::write(out.join("catalog.rs"), code).expect("catalog index");
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .windows_attributes(tauri_build::WindowsAttributes::new_without_app_manifest())
            .app_manifest(tauri_build::AppManifest::new().commands(&[
                "close_reviewed",
                "export_report",
                "scan",
                "build_plan",
                "dry_run",
                "execute",
                "cancel",
                "get_settings",
                "set_settings",
                "get_last_report",
                "enable_all_accounts_mode",
            ])),
    )
    .expect("Tauri command permissions");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc")
    {
        let manifest = Path::new("windows-app-manifest.xml")
            .canonicalize()
            .expect("Windows manifest");
        println!("cargo:rerun-if-changed={}", manifest.display());
        // Embed at the linker so test executables also select Common Controls v6.
        println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
        println!("cargo:rustc-link-arg=/MANIFESTINPUT:{}", manifest.display());
    }
}
