use ed25519_dalek::SigningKey;
use rand_core::RngCore;
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(args)
        .output()
        .unwrap()
}
fn text(path: &Path) -> &str {
    path.to_str().unwrap()
}
#[test]
fn maintainer_tools_build_sign_verify_and_refuse_repository_keys() {
    let dir = tempfile::tempdir().unwrap();
    let mut seed = [0; 32];
    rand_core::OsRng.fill_bytes(&mut seed);
    let key = SigningKey::from_bytes(&seed);
    let private = dir.path().join("throw-away-test-seed");
    let public = dir.path().join("test-public-key");
    let changelog = dir.path().join("changes.txt");
    let payload = dir.path().join("payload.json");
    let bundle = dir.path().join("signed.json");
    fs::write(&private, seed).unwrap();
    fs::write(&public, key.verifying_key().to_bytes()).unwrap();
    fs::write(
        &changelog,
        "Fixture release; unchanged rules and limitations.",
    )
    .unwrap();
    assert!(run(&["catalog-validate"]).status.success());
    let version = (everyout_catalog_update::BUNDLED_VERSION + 1).to_string();
    assert!(
        run(&["catalog-bundle", &version, text(&changelog), text(&payload)])
            .status
            .success()
    );
    let signed = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["catalog-sign", text(&payload), text(&bundle)])
        .env("EVERYOUT_CATALOG_PRIVATE_KEY_PATH", &private)
        .output()
        .unwrap();
    assert!(
        signed.status.success(),
        "{}",
        String::from_utf8_lossy(&signed.stderr)
    );
    let output = run(&["catalog-verify", text(&bundle), text(&public)]);
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout)
        .contains(&format!("Verified catalog version {version}")));
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let rejected = run(&[
        "catalog-sign",
        text(&payload),
        text(&bundle),
        text(&root.join("Cargo.toml")),
    ]);
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr)
        .contains("private key must be outside repository"));
    fs::write(&bundle, b"tampered bundle").unwrap();
    assert!(!run(&["catalog-verify", text(&bundle), text(&public)])
        .status
        .success());
}
