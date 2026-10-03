use ed25519_dalek::{Signer, SigningKey};
use everyout_catalog_update::*;
use std::{
    env, fs,
    io::Read,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .into()
}
fn collect(
    path: &Path,
    json: &mut Vec<String>,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_symlink() {
            return Err("catalog symlink rejected".into());
        }
        if entry.file_type()?.is_dir() {
            collect(&entry.path(), json)?;
        } else if entry.path().extension().is_some_and(|e| e == "json") {
            let bytes = read_bounded(&entry.path(), MAX_MANIFEST)?;
            json.push(String::from_utf8(bytes)?);
        }
    }
    Ok(())
}
fn manifests() -> std::result::Result<Vec<Entry>, Box<dyn std::error::Error>> {
    let mut json = Vec::new();
    for dir in ["browsers", "apps", "windows-dev"] {
        collect(&root().join("catalog").join(dir), &mut json)?;
    }
    Ok(entries(json)?)
}
fn read_bounded(
    path: &Path,
    limit: usize,
) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err("input exceeds limit".into());
    }
    Ok(bytes)
}
fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("catalog-validate") if args.len() == 1 => { println!("{} manifests validated", manifests()?.len()); }
        Some("catalog-table") if args.len() == 1 || (args.len() == 2 && args[1] == "--check") => {
            let output = catalog_table(&manifests()?)?;
            let path = root().join("docs/catalog/CATALOG.md");
            if args.len() == 2 {
                if fs::read_to_string(path)?.replace("\r\n", "\n") != output { return Err("catalog table is stale".into()); }
            } else { fs::write(path, output)?; }
        }
        Some("catalog-bundle") if args.len() == 4 => {
            let version = args[1].parse::<u64>()?;
            if version <= BUNDLED_VERSION { return Err("update version must exceed bundled floor".into()); }
            let changelog = String::from_utf8(read_bounded(Path::new(&args[2]), 64 * 1024)?)?;
            let payload = serde_json::to_string(&envelope(manifests()?, version, changelog))?;
            if payload.len() > MAX_BUNDLE / 2 { return Err("payload exceeds conservative bundle budget".into()); }
            fs::write(&args[3], payload)?;
        }
        Some("catalog-sign") if args.len() == 3 || args.len() == 4 => {
            let key_path = args.get(3).cloned().or_else(|| env::var("EVERYOUT_CATALOG_PRIVATE_KEY_PATH").ok()).ok_or("private key path required")?;
            let path = fs::canonicalize(&key_path)?;
            if path.starts_with(fs::canonicalize(root())?) { return Err("private key must be outside repository".into()); }
            let mut key = Zeroizing::new(Vec::with_capacity(33));
            fs::File::open(&path)?.take(33).read_to_end(&mut key)?;
            let seed: Zeroizing<[u8;32]> = Zeroizing::new(key.as_slice().try_into().map_err(|_| "key must be a raw 32-byte Ed25519 seed")?);
            let key = SigningKey::from_bytes(&seed);
            let payload = String::from_utf8(read_bounded(Path::new(&args[1]), MAX_BUNDLE)?)?;
            let bytes = serde_json::to_vec(&SignedBundle { signature: hex::encode(key.sign(&signing_bytes(&payload)).to_bytes()), payload })?;
            // Signing invalid or unsupported declarations is refused too.
            let base = bundled(manifests()?)?;
            Trust::new(Some(key.verifying_key().to_bytes()), &base)?.verify(&bytes)?;
            fs::write(&args[2], bytes)?;
        }
        Some("catalog-verify") if args.len() == 3 => {
            let public: [u8;32] = read_bounded(Path::new(&args[2]),32)?.try_into().map_err(|_| "public key must be raw 32 bytes")?;
            let snapshot = Trust::new(Some(public), &bundled(manifests()?)?)?.verify(&read_bounded(Path::new(&args[1]), MAX_BUNDLE)?)?;
            println!("Verified catalog version {}: {}", snapshot.version, snapshot.digest);
        }
        _ => return Err("usage: catalog-validate | catalog-table [--check] | catalog-bundle VERSION CHANGELOG OUTPUT | catalog-sign PAYLOAD OUTPUT [PRIVATE_KEY_PATH] | catalog-verify BUNDLE PUBLIC_KEY_PATH".into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn table_matches_committed_catalog() {
        assert_eq!(
            fs::read_to_string(root().join("docs/catalog/CATALOG.md"))
                .unwrap()
                .replace("\r\n", "\n"),
            catalog_table(&manifests().unwrap()).unwrap()
        );
    }
}
