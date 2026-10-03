use ed25519_dalek::{Signer, SigningKey};
use everyout_catalog_update::*;
use rand_core::RngCore;

fn key() -> SigningKey {
    let mut seed = [0; 32];
    rand_core::OsRng.fill_bytes(&mut seed);
    SigningKey::from_bytes(&seed)
}
fn base() -> Snapshot {
    bundled(
        entries([include_str!("../../providers/tests/fixtures/provider.json").to_owned()]).unwrap(),
    )
    .unwrap()
}
fn sign(key: &SigningKey, payload: String) -> Vec<u8> {
    serde_json::to_vec(&SignedBundle {
        signature: hex::encode(key.sign(&signing_bytes(&payload)).to_bytes()),
        payload,
    })
    .unwrap()
}
#[test]
fn valid_signature_wrong_key_tampering_and_weak_key() {
    let key = key();
    let base = base();
    let trust = Trust::new(Some(key.verifying_key().to_bytes()), &base).unwrap();
    let payload =
        serde_json::to_string(&envelope(base.entries.clone(), 2, "Changes".into())).unwrap();
    let bytes = sign(&key, payload.clone());
    assert_eq!(trust.verify(&bytes).unwrap().version, 2);
    assert!(matches!(
        Trust::new(Some(super_key().verifying_key().to_bytes()), &base)
            .unwrap()
            .verify(&bytes),
        Err(Error::Signature)
    ));
    let mut tampered: SignedBundle = serde_json::from_slice(&bytes).unwrap();
    tampered.payload = tampered.payload.replace("Changes", "Forged changes");
    assert!(matches!(
        trust.verify(&serde_json::to_vec(&tampered).unwrap()),
        Err(Error::Signature)
    ));
    tampered.payload = payload;
    tampered.signature = "00".repeat(64);
    assert!(matches!(
        trust.verify(&serde_json::to_vec(&tampered).unwrap()),
        Err(Error::Signature)
    ));
    let mut weak = [0; 32];
    weak[0] = 1;
    assert!(matches!(
        Trust::new(Some(weak), &base),
        Err(Error::Signature)
    ));
}
fn super_key() -> SigningKey {
    key()
}
#[test]
fn signed_malformed_membership_ambiguous_json_and_unsupported_formats_rejected() {
    let key = key();
    let base = base();
    let trust = Trust::new(Some(key.verifying_key().to_bytes()), &base).unwrap();
    let original = envelope(base.entries.clone(), 2, "Changes".into());
    let verify = |e: &Envelope| trust.verify(&sign(&key, serde_json::to_string(e).unwrap()));
    let mut e = original.clone();
    e.entries[0].manifest = "{}".into();
    assert!(matches!(verify(&e), Err(Error::Manifest)));
    let mut e = original.clone();
    e.entries.push(e.entries[0].clone());
    assert!(matches!(verify(&e), Err(Error::Manifest)));
    let mut e = original.clone();
    e.entries[0].sha256 = "00".repeat(32);
    assert!(matches!(verify(&e), Err(Error::Manifest)));
    let mut e = original.clone();
    e.product = "another-product".into();
    assert!(matches!(verify(&e), Err(Error::Compatibility)));
    e = original.clone();
    e.min_engine = 2;
    assert!(matches!(verify(&e), Err(Error::Compatibility)));
    e = original.clone();
    e.version = 0;
    assert!(matches!(verify(&e), Err(Error::Compatibility)));
    let payload = serde_json::to_string(&original).unwrap().replacen(
        "\"format\":1",
        "\"format\":1,\"format\":1",
        1,
    );
    assert!(matches!(
        trust.verify(&sign(&key, payload)),
        Err(Error::Format)
    ));
    let mut e = original;
    e.entries[0].manifest = e.entries[0].manifest.replacen(
        "\"format_version\":1",
        "\"format_version\":1,\"format_version\":1",
        1,
    );
    assert!(matches!(verify(&e), Err(Error::Format)));
    let mut bad: serde_json::Value = serde_json::from_str(&base.entries[0].manifest).unwrap();
    bad["roots"][0]["relative"] = serde_json::json!("../escape");
    assert!(matches!(entries([bad.to_string()]), Err(Error::Manifest)));
    let mut e = envelope(base.entries.clone(), 2, "Changes".into());
    let mut m: serde_json::Value = serde_json::from_str(&e.entries[0].manifest).unwrap();
    m["cleaning_methods"][0] = serde_json::json!({"id":"remove-session-file", "kind":"exception-adapter", "adapter_id":"downloaded-code", "blockers":["unsupported"], "effects":["removal"]});
    let method = m["cleaning_methods"][0]["id"].clone();
    for artifact in m["session_locations"].as_array_mut().unwrap() {
        artifact["method"] = method.clone();
    }
    // This candidate is schema-valid but introduces a new adapter capability.
    e.entries = entries([m.to_string()]).unwrap();
    assert!(matches!(verify(&e), Err(Error::UnsupportedAdapter)));
}
#[test]
fn bounds_truncation_and_transport_configuration() {
    let key = key();
    let base = base();
    let trust = Trust::new(Some(key.verifying_key().to_bytes()), &base).unwrap();
    assert!(matches!(
        trust.verify(&vec![b' '; MAX_BUNDLE + 1]),
        Err(Error::Bounds)
    ));
    let bytes = sign(
        &key,
        serde_json::to_string(&envelope(base.entries, 2, "Changes".into())).unwrap(),
    );
    assert!(matches!(
        trust.verify(&bytes[..bytes.len() - 1]),
        Err(Error::Format)
    ));
    assert!(entries([" ".repeat(MAX_MANIFEST + 1)]).is_err());
    assert!(strict_json::<serde_json::Value>(
        format!("{}0{}", "[".repeat(130), "]".repeat(130)).as_bytes()
    )
    .is_err());
    for url in [
        "http://example.com/catalog",
        "https://user:pass@example.com/catalog",
        "https://example.com/catalog?machine=id",
        "https://example.com/catalog#fragment",
    ] {
        assert!(transport::HttpsSource::new(url).is_err());
    }
    assert!(transport::HttpsSource::new("https://example.com/catalog").is_ok());
}
