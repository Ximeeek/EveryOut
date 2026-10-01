//! Test-only synthetic trees. No existing directory or user profile can be adopted.
use std::{collections::BTreeMap, fs, io, path::Path};

const PROFILES_INI: &[u8] =
    b"[Profile0]\nName=synthetic\nIsRelative=1\nPath=Profiles/lab.default\n";

/// Owns a fresh temporary directory; payloads are invented, never imported.
pub struct FixtureTree {
    directory: tempfile::TempDir,
}

/// Relative paths and sizes only. Directory paths end in `/` and have size zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot(pub BTreeMap<String, u64>);

impl FixtureTree {
    pub fn empty() -> io::Result<Self> {
        Ok(Self {
            directory: tempfile::Builder::new()
                .prefix("everyout-fixture-")
                .tempdir()?,
        })
    }

    pub fn profiles(seed: u64) -> io::Result<Self> {
        let fixture = Self::empty()?;
        for (path, size) in profile_layout() {
            let destination = fixture.path().join(&path);
            if path.ends_with('/') {
                fs::create_dir_all(destination)?;
            } else {
                fs::create_dir_all(destination.parent().expect("fixture parent"))?;
                // Reproducible opaque bytes, not an authentication format or secret.
                let mut state = seed;
                let bytes: Vec<u8> = (0..size)
                    .map(|_| {
                        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                        (state >> 32) as u8
                    })
                    .collect();
                fs::write(destination, bytes)?;
            }
        }
        // Invented profile metadata only, never read by the platform adapter.
        fs::write(
            fixture.path().join("RoamingAppData/Firefox/profiles.ini"),
            PROFILES_INI,
        )?;
        Ok(fixture)
    }

    /// Only for synthetic seeding and observation; not a deletion capability.
    pub fn path(&self) -> &Path {
        self.directory.path()
    }

    /// Observe a quiescent owned fixture. Reject redirections; never open payloads.
    pub fn snapshot(&self) -> io::Result<Snapshot> {
        let mut entries = BTreeMap::new();
        capture(self.path(), self.path(), &mut entries, 0)?;
        Ok(Snapshot(entries))
    }
}

fn capture(
    root: &Path,
    directory: &Path,
    entries: &mut BTreeMap<String, u64>,
    depth: usize,
) -> io::Result<()> {
    if depth > 64 || entries.len() > 10_000 {
        return Err(io::Error::other("fixture too large"));
    }
    let metadata = fs::symlink_metadata(directory)?;
    #[cfg(windows)]
    let redirected = {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    };
    #[cfg(not(windows))]
    let redirected = metadata.file_type().is_symlink();
    if redirected {
        return Err(io::Error::other("redirected fixture"));
    }
    if directory != root {
        let relative = directory.strip_prefix(root).map_err(io::Error::other)?;
        let mut name = relative
            .to_str()
            .ok_or_else(|| io::Error::other("non-Unicode fixture"))?
            .replace('\\', "/");
        if metadata.is_dir() {
            name.push('/');
        } else if !metadata.is_file() {
            return Err(io::Error::other("special fixture object"));
        }
        entries.insert(name, if metadata.is_dir() { 0 } else { metadata.len() });
    }
    if metadata.is_dir() {
        for entry in fs::read_dir(directory)? {
            capture(root, &entry?.path(), entries, depth + 1)?;
        }
    }
    Ok(())
}

/// Documented synthetic file layout; parent directories are created implicitly.
pub fn profile_layout() -> Vec<(String, u64)> {
    let mut files = Vec::new();
    for profile in ["Default", "Profile 1"] {
        for (artifact, size) in [
            ("Network/Cookies", 64),
            ("Network/Cookies-wal", 16),
            ("Network/Cookies-shm", 8),
            ("Local Storage/leveldb/000001.log", 32),
            ("Session Storage/000001.log", 24),
            ("IndexedDB/lab.indexeddb.leveldb/000001.log", 40),
            ("Service Worker/Database/000001.log", 20),
            ("Extensions/synthetic/1.0/manifest.json", 12),
            ("Local Extension Settings/synthetic/000001.log", 28),
            ("Bookmarks", 13),
            ("History", 17),
        ] {
            files.push((
                format!("LocalAppData/Chromium/User Data/{profile}/{artifact}"),
                size,
            ));
        }
    }
    for (path, size) in [
        (
            "RoamingAppData/Firefox/profiles.ini",
            PROFILES_INI.len() as u64,
        ),
        (
            "RoamingAppData/Firefox/Profiles/lab.default/cookies.sqlite",
            64,
        ),
        (
            "RoamingAppData/Firefox/Profiles/lab.default/cookies.sqlite-wal",
            16,
        ),
        (
            "RoamingAppData/Firefox/Profiles/lab.default/cookies.sqlite-shm",
            8,
        ),
        (
            "RoamingAppData/Firefox/Profiles/lab.default/storage/default/lab/opaque",
            32,
        ),
        (
            "RoamingAppData/Firefox/Profiles/lab.default/places.sqlite",
            19,
        ),
        ("RoamingAppData/Electron Lab/Network/Cookies", 64),
        (
            "RoamingAppData/Electron Lab/Local Storage/leveldb/000001.log",
            32,
        ),
        ("RoamingAppData/Electron Lab/Session Storage/000001.log", 24),
        ("RoamingAppData/Electron Lab/IndexedDB/lab/opaque", 40),
        ("RoamingAppData/Electron Lab/drafts/preserved", 21),
        ("LocalAppData/Steam/config/loginusers.vdf", 32),
        ("LocalAppData/Steam/ssfn0000000001", 24),
        ("LocalAppData/Steam/steamapps/preserved", 23),
        (
            "LocalAppData/Packages/EveryOutLab_synthetic/LocalState/session",
            32,
        ),
        (
            "LocalAppData/Packages/EveryOutLab_synthetic/LocalState/preserved",
            27,
        ),
        ("LocalAppData/unknown version żółć/residue", 11),
        ("outside-allowed/canary", 29),
        ("empty/", 0),
    ] {
        files.push((path.into(), size));
    }
    files
}

impl Snapshot {
    pub fn assert_removed(&self, after: &Self, paths: &[&str]) {
        for path in paths {
            assert!(self.0.contains_key(*path), "target missing before: {path}");
            assert!(!after.0.contains_key(*path), "target survives: {path}");
        }
    }

    /// Exact metadata difference: removals only, with no added or resized entries.
    pub fn assert_nothing_else_changed(&self, after: &Self, removed: &[&str]) {
        self.assert_removed(after, removed);
        let mut expected = self.0.clone();
        for path in removed {
            expected.remove(*path);
        }
        assert_eq!(expected, after.0, "unexpected fixture metadata effects");
    }

    pub fn assert_second_run_changes_nothing(&self, second: &Self) {
        assert_eq!(self, second, "second run changed fixture metadata");
    }
}
