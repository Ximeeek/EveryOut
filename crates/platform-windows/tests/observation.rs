#![cfg(windows)]
use everyout_core_model::{observation::*, *};
use everyout_platform_windows::{observation::*, FixtureFolders, KnownFolder, RootResolver};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

// A copied, randomly named test executable acts as an unknown application.
// IPC commands are fixture controls; the observer never reads storage contents.
#[test]
fn synthetic_application_process() {
    let Some(root) = std::env::var_os("EVERYOUT_TEACH_FIXTURE") else {
        return;
    };
    let root = PathBuf::from(root);
    let mode = std::env::var("EVERYOUT_CAUSAL_MODE").unwrap_or_default();
    assert!(root.join("fixture.marker").is_file());
    let profile = root.join(
        std::env::var("EVERYOUT_PROFILE_DIRECTORY")
            .unwrap_or_else(|_| "SomeVendor/RandomProfile82".into()),
    );
    fs::create_dir_all(profile.join("Cache")).unwrap();
    fs::create_dir_all(profile.join("Logs")).unwrap();
    // Missing stores are recreated, as a real application does on launch. Only
    // the fixture harness interprets invented state; EveryOut observes metadata.
    fs::create_dir_all(profile.join("Local Storage/leveldb")).unwrap();
    if mode == "dual" {
        fs::create_dir_all(profile.join("IndexedDB")).unwrap();
    }
    if mode == "sqlite" && !profile.join("accounts.db").exists() {
        fs::write(profile.join("accounts.db"), b"").unwrap();
        // Include an originally absent companion recreated during B.
        fs::write(profile.join("accounts.db-journal"), b"").unwrap();
    }
    let noise = || {
        for path in ["Logs/activity.log", "Cache/data"] {
            fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(profile.join(path))
                .unwrap()
                .write_all(b"opaque synthetic activity\n")
                .unwrap();
        }
    };
    noise();
    println!("ACK");
    std::io::stdout().flush().unwrap();
    for command in std::io::stdin().lock().lines() {
        let command = command.unwrap();
        let auth = profile.join("Local Storage/leveldb");
        match command.as_str() {
            "login" => {
                fs::create_dir_all(&auth).unwrap();
                fs::write(auth.join("000123.ldb"), b"invented opaque state").unwrap();
                if mode == "sqlite" {
                    fs::remove_file(auth.join("000123.ldb")).unwrap();
                    for suffix in ["", "-wal", "-shm"] {
                        fs::write(
                            profile.join(format!("accounts.db{suffix}")),
                            b"opaque invented database state",
                        )
                        .unwrap();
                    }
                    let _ = fs::remove_file(profile.join("accounts.db-journal"));
                }
                if mode == "dual" {
                    fs::write(profile.join("IndexedDB/state"), b"invented second state").unwrap();
                }
                if mode == "false-correlation" {
                    fs::write(root.join("remote-state.marker"), b"invented external state")
                        .unwrap();
                }
            }
            "logout" => {
                if mode == "sqlite" {
                    fs::write(profile.join("accounts.db"), b"").unwrap();
                    for suffix in ["-wal", "-shm"] {
                        fs::remove_file(profile.join(format!("accounts.db{suffix}"))).unwrap();
                    }
                } else {
                    fs::remove_file(auth.join("000123.ldb")).unwrap();
                }
                if mode == "dual" {
                    fs::remove_file(profile.join("IndexedDB/state")).unwrap();
                }
                if mode == "false-correlation" {
                    fs::remove_file(root.join("remote-state.marker")).unwrap();
                }
            }
            "state" => {
                let signed_in = if mode == "false-correlation" {
                    root.join("remote-state.marker").exists()
                } else if mode == "sqlite" {
                    fs::metadata(profile.join("accounts.db")).unwrap().len() > 0
                } else {
                    auth.join("000123.ldb").exists()
                        || mode == "dual" && profile.join("IndexedDB/state").exists()
                };
                println!("STATE:{signed_in}");
            }
            "settled" => {}
            "stop" => {
                noise();
                break;
            }
            _ => panic!("unexpected fixture command"),
        }
        noise();
        println!("ACK");
        std::io::stdout().flush().unwrap();
    }
}
struct SyntheticApp {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}
impl SyntheticApp {
    fn launch(executable: &Path, root: &Path) -> Self {
        Self::launch_mode(executable, root, "")
    }
    fn launch_mode(executable: &Path, root: &Path, mode: &str) -> Self {
        Self::launch_at(executable, root, mode, "SomeVendor/RandomProfile82")
    }
    fn launch_at(executable: &Path, root: &Path, mode: &str, profile: &str) -> Self {
        let mut child = Command::new(executable)
            .args(["--exact", "synthetic_application_process", "--nocapture"])
            .env("EVERYOUT_TEACH_FIXTURE", root)
            .env("EVERYOUT_CAUSAL_MODE", mode)
            .env("EVERYOUT_PROFILE_DIRECTORY", profile)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let output = BufReader::new(child.stdout.take().unwrap());
        let mut app = Self {
            child,
            input,
            output,
        };
        app.ack();
        app
    }
    fn ack(&mut self) {
        loop {
            let mut line = String::new();
            assert!(
                self.output.read_line(&mut line).unwrap() > 0,
                "fixture exited before ACK"
            );
            if line.trim() == "ACK" {
                break;
            }
        }
    }
    fn send(&mut self, message: &str) {
        writeln!(self.input, "{message}").unwrap();
        self.input.flush().unwrap();
        self.ack();
    }
    fn stop(mut self) {
        writeln!(self.input, "stop").unwrap();
        self.input.flush().unwrap();
        assert!(self.child.wait().unwrap().success());
    }
    fn state(&mut self) -> bool {
        writeln!(self.input, "state").unwrap();
        self.input.flush().unwrap();
        loop {
            let mut line = String::new();
            assert!(self.output.read_line(&mut line).unwrap() > 0);
            if let Some(state) = line.trim().strip_prefix("STATE:") {
                let state = state == "true";
                self.ack();
                return state;
            }
        }
    }
    fn stop_soon(self) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(200));
            self.stop();
        })
    }
}
impl Drop for SyntheticApp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn synthetic_unknown_executable_discovers_unrelated_root_and_observes_two_live_cycles() {
    let fixture = FixtureFolders::create().unwrap();
    let root = fixture.path();
    fs::write(root.join("fixture.marker"), b"synthetic").unwrap();
    fs::create_dir(root.join("installation")).unwrap();
    let name = format!("TotallyUnknownApp-{}.exe", now_ms());
    let executable = root.join("installation").join(&name);
    fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
    let mut teach = TeachController::start(
        &executable,
        None,
        vec![fixture.resolve(KnownFolder::LocalAppData).unwrap()],
        vec![],
        "unknown-live".into(),
    )
    .unwrap();
    assert_eq!(
        teach.session.binding.identity.state,
        ApplicationIdentity::Exact
    );
    let app = SyntheticApp::launch(&executable, root);
    thread::sleep(Duration::from_millis(100));
    teach.tick();
    teach.end_discovery();
    assert!(teach
        .view()
        .candidate_roots
        .iter()
        .any(|r| r.ends_with("SomeVendor")));
    assert!(!teach
        .view()
        .candidate_roots
        .iter()
        .any(|r| r.contains(&name)));
    app.stop();
    fs::create_dir_all(root.join("SomeVendor/RandomProfile82/Local Storage/leveldb")).unwrap();
    for _ in 0..2 {
        teach.begin_cycle().unwrap();
        let mut app = SyntheticApp::launch(&executable, root);
        teach.advance(Some(false)).unwrap();
        app.send("login");
        teach.advance(Some(true)).unwrap();
        app.send("settled");
        teach.advance(Some(true)).unwrap();
        app.stop();
        let mut app = SyntheticApp::launch(&executable, root);
        teach.advance(Some(true)).unwrap();
        app.send("logout");
        teach.advance(Some(false)).unwrap();
        app.stop();
        teach.advance(Some(false)).unwrap();
    }
    let record = teach.finish();
    assert_eq!(record.status, LearnedStatus::Observed, "{record:#?}");
    let root = record
        .roots
        .iter()
        .find(|r| r.root.ends_with("SomeVendor"))
        .unwrap();
    let auth = root
        .families
        .iter()
        .find(|f| f.family == "randomprofile82/local storage")
        .unwrap();
    assert_eq!(auth.verdict, ObservationVerdict::StronglyObserved);
    let cache = root
        .families
        .iter()
        .find(|f| f.family == "randomprofile82/cache")
        .unwrap();
    assert_eq!(cache.verdict, ObservationVerdict::Noise);
    assert_eq!(
        record.evidence(root, auth).authentication_scope.state,
        AuthenticationScope::Observed
    );
    assert!(
        !record
            .evidence(root, auth)
            .decide(Support::Candidate, &[], LossAssessment::Unknown, &[], &[])
            .action_allowed
    );
    assert_eq!(
        record.evidence(root, auth).authority,
        OperationAuthority::Unreviewed
    );
}
#[test]
fn native_extended_and_standard_watchers_report_subtree_changes_and_cancel_safely() {
    for standard in [false, true] {
        let fixture = FixtureFolders::create().unwrap();
        let root = fixture.resolve(KnownFolder::LocalAppData).unwrap();
        let mut watcher = if standard {
            DirectoryWatcherBackend::start_standard(root)
        } else {
            DirectoryWatcherBackend::start(root)
        }
        .unwrap();
        if standard {
            assert_eq!(watcher.mode(), WatcherMode::Standard);
        }
        fs::create_dir(fixture.path().join("Nested")).unwrap();
        fs::write(
            fixture.path().join("Nested/a.db"),
            b"opaque synthetic fixture",
        )
        .unwrap();
        fs::rename(
            fixture.path().join("Nested/a.db"),
            fixture.path().join("Nested/b.db"),
        )
        .unwrap();
        fs::remove_file(fixture.path().join("Nested/b.db")).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut events = vec![];
        while Instant::now() < deadline {
            events.extend(watcher.poll().unwrap().events);
            if events
                .iter()
                .any(|e| e.path == "Nested/b.db" && e.kind == ChangeKind::Remove)
            {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        for kind in [
            ChangeKind::Create,
            ChangeKind::RenameOld,
            ChangeKind::RenameNew,
            ChangeKind::Remove,
        ] {
            assert!(events.iter().any(|e| e.kind == kind), "missing {kind:?}");
        }
        drop(watcher);
    }
}
#[test]
fn bounded_snapshot_and_overflow_rescan_report_completeness_and_physical_metadata() {
    let fixture = FixtureFolders::create().unwrap();
    fs::write(
        fixture.path().join("unknown-state.db"),
        b"unread synthetic bytes",
    )
    .unwrap();
    let root = fixture.resolve(KnownFolder::LocalAppData).unwrap();
    let captured = snapshot(&root, SnapshotBudget::default()).unwrap();
    assert_eq!(captured.completeness, Completeness::Complete);
    let entry = &captured.entries["unknown-state.db"];
    assert!(entry.parent.is_some());
    assert!(entry.write_ticks > 0);
    assert!(entry.change_ticks > 0);
    assert_eq!(
        snapshot(
            &root,
            SnapshotBudget {
                entries: 0,
                ..Default::default()
            }
        )
        .unwrap()
        .completeness,
        Completeness::Incomplete
    );
    let recovered = recover_snapshot(&root, SnapshotBudget::default()).unwrap();
    assert_eq!(recovered.completeness, Completeness::RecoveredByRescan);
    assert!(recovered
        .provenance
        .iter()
        .any(|p| p.reason_code == "history-lost-metadata-rescan"));
}
#[test]
fn image_replacement_during_discovery_makes_session_stale_and_retains_history() {
    let fixture = FixtureFolders::create().unwrap();
    fs::create_dir(fixture.path().join("installation")).unwrap();
    let executable = fixture.path().join("installation/Unknown.exe");
    fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
    let mut teach = TeachController::start(
        &executable,
        None,
        vec![fixture.resolve(KnownFolder::LocalAppData).unwrap()],
        vec![],
        "update".into(),
    )
    .unwrap();
    fs::rename(&executable, executable.with_extension("old")).unwrap();
    fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
    thread::sleep(Duration::from_millis(1100));
    teach.tick();
    assert_eq!(teach.view().stage, TeachStage::Stale);
    assert_eq!(teach.finish().status, LearnedStatus::Stale);
}

#[test]
fn framework_metadata_change_invalidates_even_when_executable_is_unchanged() {
    let fixture = FixtureFolders::create().unwrap();
    let installation = fixture.path().join("installation");
    fs::create_dir(&installation).unwrap();
    let executable = installation.join("UnknownFramework.exe");
    fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
    fs::write(installation.join("libcef.dll"), b"invented framework bytes").unwrap();
    let mut teach = TeachController::start(
        &executable,
        None,
        vec![fixture.resolve(KnownFolder::LocalAppData).unwrap()],
        vec![],
        "framework".into(),
    )
    .unwrap();
    assert_eq!(teach.session.binding.framework_fingerprint.len(), 1);
    fs::write(
        installation.join("libcef.dll"),
        b"changed opaque framework metadata and size",
    )
    .unwrap();
    thread::sleep(Duration::from_millis(1100));
    teach.tick();
    assert_eq!(teach.view().stage, TeachStage::Stale);
    assert_eq!(teach.finish().status, LearnedStatus::Stale);
}

use everyout_core_model::local_validation::*;
use everyout_platform_windows::{validation::*, AllowedRoot};
struct FixtureGuard {
    shared: std::cell::Cell<bool>,
}
impl OwnershipGuard for FixtureGuard {
    fn check(
        &self,
        _: &ApplicationBinding,
        _: &[RootObservation],
    ) -> everyout_platform_windows::Result<()> {
        if self.shared.get() {
            Err(everyout_platform_windows::PlatformError {
                kind: ErrorKind::OwnershipConflict,
                os_code: None,
                applied: 0,
            })
        } else {
            Ok(())
        }
    }
}
struct CausalFixture {
    fixture: FixtureFolders,
    executable: PathBuf,
    learned: LearnedObservation,
    base: AllowedRoot,
    store: JournalStore,
    guard: FixtureGuard,
    mode: String,
    profile: String,
}
impl CausalFixture {
    fn teach(mode: &str) -> Self {
        let fixture = FixtureFolders::create().unwrap();
        let path = fixture.path();
        fs::write(path.join("fixture.marker"), b"synthetic").unwrap();
        fs::create_dir(path.join("installation")).unwrap();
        fs::create_dir(path.join("config")).unwrap();
        let executable = path
            .join("installation")
            .join(format!("TotallyUnknownApp-{}.exe", random_id().unwrap()));
        let profile = format!(
            "UnknownRoot-{}/UnknownProfile-{}",
            random_id().unwrap(),
            random_id().unwrap()
        );
        fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
        set_fixture_version(&executable, "1.0.0");
        let base = fixture.resolve(KnownFolder::LocalAppData).unwrap();
        let mut teach = TeachController::start(
            &executable,
            None,
            vec![base.clone()],
            vec![],
            random_id().unwrap(),
        )
        .unwrap();
        let app = SyntheticApp::launch_at(&executable, path, mode, &profile);
        thread::sleep(Duration::from_millis(100));
        teach.tick();
        teach.end_discovery();
        app.stop();
        for _ in 0..2 {
            teach.begin_cycle().unwrap();
            let mut app = SyntheticApp::launch_at(&executable, path, mode, &profile);
            teach.advance(Some(false)).unwrap();
            app.send("login");
            teach.advance(Some(true)).unwrap();
            app.send("settled");
            teach.advance(Some(true)).unwrap();
            app.stop();
            let mut app = SyntheticApp::launch_at(&executable, path, mode, &profile);
            teach.advance(Some(true)).unwrap();
            app.send("logout");
            teach.advance(Some(false)).unwrap();
            app.stop();
            teach.advance(Some(false)).unwrap();
        }
        let learned = teach.finish();
        assert_eq!(learned.status, LearnedStatus::Observed, "{learned:#?}");
        let mut app = SyntheticApp::launch_at(&executable, path, mode, &profile);
        app.send("login");
        assert!(app.state());
        app.stop();
        let store = JournalStore::open(&path.join("config/validation")).unwrap();
        Self {
            fixture,
            executable,
            learned,
            base,
            store,
            guard: FixtureGuard {
                shared: std::cell::Cell::new(false),
            },
            mode: mode.into(),
            profile,
        }
    }
    fn app(&self) -> SyntheticApp {
        SyntheticApp::launch_at(
            &self.executable,
            self.fixture.path(),
            &self.mode,
            &self.profile,
        )
    }
    fn storage_root(&self) -> AllowedRoot {
        self.base
            .discovery_descendant(self.profile.split('/').next().unwrap())
            .unwrap()
    }
    fn auth_key(&self) -> String {
        format!("{}/Local Storage", self.profile.split('/').nth(1).unwrap())
    }
    fn controller(&self) -> ValidationController {
        ValidationController::start(
            self.learned.clone(),
            std::slice::from_ref(&self.base),
            &self.store,
            &self.guard,
        )
        .unwrap()
    }
    fn phase(&self, controller: &mut ValidationController) -> bool {
        let mut app = self.app();
        let signed_in = app.state();
        let thread = app.stop_soon();
        let result = controller.confirm(
            if signed_in {
                AppOutcome::SignedIn
            } else {
                AppOutcome::SignedOut
            },
            &self.store,
            &self.guard,
        );
        thread.join().unwrap();
        result.unwrap_or_else(|error| {
            panic!(
                "phase {:?}: {error:?}; journals: {:?}",
                controller.view(),
                self.store.journals()
            )
        });
        signed_in
    }
    fn validate(&self) -> LocalValidatedRule {
        let mut controller = self.controller();
        while controller.view().stage == ValidationStage::ReadyControl {
            controller.begin_trial(&self.guard).unwrap();
            assert!(self.phase(&mut controller));
            self.phase(&mut controller);
            assert!(self.phase(&mut controller));
        }
        assert_eq!(
            controller.view().stage,
            ValidationStage::AwaitingAcceptance,
            "{:#?}",
            controller.view()
        );
        let rule = controller.accept_losses(&self.store, &self.guard).unwrap();
        assert_eq!(rule.repetitions, 2);
        assert!(rule.qualified());
        rule
    }
}

#[test]
fn unknown_app_p1_p2_p3_local_apply_and_changed_executable_stales_rule() {
    let fixture = CausalFixture::teach("");
    assert_eq!(fixture.learned.binding.version.as_deref(), Some("1.0.0"));
    assert_eq!(
        fixture.learned.binding.identity.state,
        ApplicationIdentity::Exact
    );
    let auth = fixture.learned.roots[0]
        .families
        .iter()
        .find(|f| approved_family(f))
        .unwrap();
    assert!(
        !fixture
            .learned
            .evidence(&fixture.learned.roots[0], auth)
            .decide(Support::Candidate, &[], LossAssessment::Unknown, &[], &[])
            .action_allowed
    );
    let rule = fixture.validate();
    assert_eq!(rule.scope.len(), 1);
    assert!(rule.scope[0].family.ends_with("local storage"));
    assert_eq!(
        rule.decision().evidence.authentication_scope.state,
        AuthenticationScope::LocallyValidated
    );
    assert_eq!(
        rule.decision().evidence.authority,
        OperationAuthority::LocalBounded
    );
    assert!(rule.decision().action_allowed);
    assert_ne!(rule.preservation, PreservationState::Validated);
    write_p3_examples(&fixture, &rule);
    let original = rule.artifacts[0].physical.unwrap();
    let root = fixture.storage_root();
    assert_eq!(
        snapshot(&root, SnapshotBudget::default()).unwrap().entries[&fixture.auth_key()].identity,
        original
    );
    assert!(!fixture.store.pending().unwrap());
    let authority = LocalLogoutAuthority::bind(
        rule.clone(),
        std::slice::from_ref(&fixture.base),
        &fixture.store,
        &fixture.guard,
    )
    .unwrap();
    assert!(
        authority
            .apply(true, &fixture.store, &fixture.guard)
            .unwrap()
            > 0
    );
    let mut app = fixture.app();
    assert!(!app.state());
    app.stop();
    set_fixture_version(&fixture.executable, "2.0.0");
    let mut updated = everyout_platform_windows::win32_identity::Win32Snapshot::default();
    updated
        .observe_executable(
            &fixture.executable,
            everyout_platform_windows::win32_identity::IdentitySource::Selected,
            None,
        )
        .unwrap();
    assert_eq!(
        application_binding(&updated.applications[0], None)
            .unwrap()
            .version
            .as_deref(),
        Some("2.0.0")
    );
    assert!(LocalLogoutAuthority::bind(
        rule.clone(),
        std::slice::from_ref(&fixture.base),
        &fixture.store,
        &fixture.guard
    )
    .is_err());
    fixture.store.mark_stale(&rule.id).unwrap();
    assert!(fixture.store.rules().unwrap()[0].stale);
    assert_eq!(fixture.store.rules().unwrap().len(), 1);
}

fn write_p3_examples(fixture: &CausalFixture, rule: &LocalValidatedRule) {
    let Some(directory) = std::env::var_os("EVERYOUT_P3_EXAMPLES") else {
        return;
    };
    let directory = PathBuf::from(directory);
    assert!(directory.is_dir());
    let root = &fixture.learned.roots[0];
    let family = root.families.iter().find(|f| approved_family(f)).unwrap();
    let before = fixture.learned.evidence(root, family).decide(
        Support::Candidate,
        &[],
        LossAssessment::Unknown,
        &[],
        &[],
    );
    let journal = fixture.store.journals().unwrap().pop().unwrap();
    let values = [
        (
            "local-validated-rule.json",
            serde_json::to_value(rule).unwrap(),
        ),
        (
            "p3-decision-before.json",
            serde_json::to_value(before).unwrap(),
        ),
        (
            "p3-decision-after.json",
            serde_json::to_value(rule.decision()).unwrap(),
        ),
        (
            "p3-validation-journal.json",
            serde_json::to_value(journal).unwrap(),
        ),
    ];
    fn sanitize(
        value: &mut serde_json::Value,
        prefix: &str,
        ids: &mut std::collections::BTreeMap<String, u64>,
    ) {
        match value {
            serde_json::Value::String(text) => {
                *text = text.replace(prefix, "C:\\Synthetic\\EveryOut");
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    sanitize(value, prefix, ids);
                }
            }
            serde_json::Value::Object(fields) => {
                if fields.len() == 2
                    && fields.contains_key("volume")
                    && fields.contains_key("index")
                {
                    let key = format!("{}:{}", fields["volume"], fields["index"]);
                    let next = ids.len() as u64 + 1;
                    let id = *ids.entry(key).or_insert(next);
                    fields.insert("volume".into(), serde_json::json!(1));
                    fields.insert("index".into(), serde_json::json!(id.to_string()));
                } else {
                    for value in fields.values_mut() {
                        sanitize(value, prefix, ids);
                    }
                }
            }
            _ => {}
        }
    }
    let prefix = fixture.fixture.path().to_string_lossy().into_owned();
    let mut identities = std::collections::BTreeMap::new();
    for (name, mut value) in values {
        sanitize(&mut value, &prefix, &mut identities);
        fs::write(
            directory.join(name),
            serde_json::to_vec_pretty(&value).unwrap(),
        )
        .unwrap();
    }
}

// PE version metadata belongs to the synthetic application, independently of the
// catalog. Only the freshly copied fixture executable's resource is edited.
fn set_fixture_version(executable: &Path, version: &str) {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::System::LibraryLoader::{
        BeginUpdateResourceW, EndUpdateResourceW, UpdateResourceW,
    };
    fn block(
        key: &str,
        kind: u16,
        value: &[u8],
        value_length: u16,
        children: &[Vec<u8>],
    ) -> Vec<u8> {
        let mut bytes = vec![0, 0];
        bytes.extend(value_length.to_le_bytes());
        bytes.extend(kind.to_le_bytes());
        for word in key.encode_utf16().chain(Some(0)) {
            bytes.extend(word.to_le_bytes());
        }
        while !bytes.len().is_multiple_of(4) {
            bytes.push(0);
        }
        bytes.extend(value);
        for child in children {
            while !bytes.len().is_multiple_of(4) {
                bytes.push(0);
            }
            bytes.extend(child);
        }
        let length = bytes.len() as u16;
        bytes[..2].copy_from_slice(&length.to_le_bytes());
        bytes
    }
    let text: Vec<u8> = version
        .encode_utf16()
        .chain(Some(0))
        .flat_map(u16::to_le_bytes)
        .collect();
    let file = block("FileVersion", 1, &text, (text.len() / 2) as u16, &[]);
    let product = block("ProductVersion", 1, &text, (text.len() / 2) as u16, &[]);
    let table = block("040904b0", 1, &[], 0, &[file, product]);
    let strings = block("StringFileInfo", 1, &[], 0, &[table]);
    let translation = block("Translation", 0, &[0x09, 0x04, 0xb0, 0x04], 4, &[]);
    let variables = block("VarFileInfo", 1, &[], 0, &[translation]);
    let fixed: Vec<u8> = [
        0xfeef04bdu32,
        0x10000,
        0x10000,
        0,
        0x10000,
        0,
        0x3f,
        0,
        0x40004,
        1,
        0,
        0,
        0,
    ]
    .into_iter()
    .flat_map(u32::to_le_bytes)
    .collect();
    let resource = block("VS_VERSION_INFO", 0, &fixed, 52, &[strings, variables]);
    let path: Vec<_> = executable
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    unsafe {
        let handle = BeginUpdateResourceW(path.as_ptr(), 0);
        assert!(!handle.is_null());
        let changed = UpdateResourceW(
            handle,
            std::ptr::without_provenance(16),
            std::ptr::without_provenance(1),
            0x0409,
            resource.as_ptr().cast(),
            resource.len() as u32,
        );
        assert_ne!(EndUpdateResourceW(handle, i32::from(changed == 0)), 0);
        assert_ne!(changed, 0);
    }
}

#[test]
fn two_cooperating_families_exclude_cache_and_require_two_fresh_final_trials() {
    let fixture = CausalFixture::teach("dual");
    let rule = fixture.validate();
    assert_eq!(rule.scope.len(), 2);
    assert!(rule
        .scope
        .iter()
        .all(|s| s.family.ends_with("local storage") || s.family.ends_with("indexeddb")));
    assert_eq!(rule.trials.len(), 5);
    assert!(rule.trials[..2]
        .iter()
        .all(|t| t.result == CausalResult::Insufficient));
    assert!(rule.trials[3..]
        .iter()
        .all(|t| t.purpose == TrialPurpose::FinalRepeat && t.result == CausalResult::Sufficient));
    LocalLogoutAuthority::bind(
        rule,
        std::slice::from_ref(&fixture.base),
        &fixture.store,
        &fixture.guard,
    )
    .unwrap()
    .apply(true, &fixture.store, &fixture.guard)
    .unwrap();
    let mut app = fixture.app();
    assert!(!app.state());
    app.stop();
}

#[test]
fn false_p2_correlation_does_not_create_local_authority() {
    let fixture = CausalFixture::teach("false-correlation");
    let mut controller = fixture.controller();
    controller.begin_trial(&fixture.guard).unwrap();
    assert!(fixture.phase(&mut controller));
    assert!(fixture.phase(&mut controller));
    assert!(fixture.phase(&mut controller));
    assert_eq!(controller.view().stage, ValidationStage::Failed);
    assert_eq!(
        controller.view().trials[0].result,
        CausalResult::Insufficient
    );
    assert!(controller
        .accept_losses(&fixture.store, &fixture.guard)
        .is_err());
    assert!(fixture.store.rules().unwrap().is_empty());
}

#[test]
fn shared_conflict_and_incomplete_observation_block_before_journal_or_mutation() {
    let fixture = CausalFixture::teach("");
    fixture.guard.shared.set(true);
    assert!(ValidationController::start(
        fixture.learned.clone(),
        std::slice::from_ref(&fixture.base),
        &fixture.store,
        &fixture.guard
    )
    .is_err());
    fixture.guard.shared.set(false);
    let mut learned = fixture.learned.clone();
    learned.completeness = Completeness::Incomplete;
    assert!(ValidationController::start(
        learned,
        std::slice::from_ref(&fixture.base),
        &fixture.store,
        &fixture.guard
    )
    .is_err());
    assert!(fixture.store.journals().unwrap().is_empty());
}

#[test]
fn crash_checkpoints_recover_original_id_without_overwriting_recreated_storage() {
    for checkpoint in [
        Checkpoint::Prepared,
        Checkpoint::Quarantined,
        Checkpoint::AppLaunched,
        Checkpoint::ReplacementObserved,
        Checkpoint::BeforeRollback,
        Checkpoint::ReplacementMoved,
        Checkpoint::RestoreTransition,
    ] {
        let fixture = CausalFixture::teach("");
        let root = fixture.storage_root();
        let before = snapshot(&root, SnapshotBudget::default()).unwrap().entries
            [&fixture.auth_key()]
            .identity;
        let mut controller = fixture.controller();
        controller.faults.crash_at = Some(checkpoint);
        controller.begin_trial(&fixture.guard).unwrap();
        let mut app = fixture.app();
        assert!(app.state());
        let thread = app.stop_soon();
        let a1 = controller.confirm(AppOutcome::SignedIn, &fixture.store, &fixture.guard);
        thread.join().unwrap();
        if a1.is_ok() {
            let mut app = fixture.app();
            assert!(!app.state());
            let thread = app.stop_soon();
            assert!(
                controller
                    .confirm(AppOutcome::SignedOut, &fixture.store, &fixture.guard)
                    .is_err(),
                "{checkpoint:?}"
            );
            thread.join().unwrap();
        }
        drop(controller);
        assert!(fixture.store.pending().unwrap(), "{checkpoint:?}");
        assert!(ValidationController::start(
            fixture.learned.clone(),
            std::slice::from_ref(&fixture.base),
            &fixture.store,
            &fixture.guard
        )
        .is_err());
        let reopened =
            JournalStore::open(&fixture.fixture.path().join("config/validation")).unwrap();
        assert_eq!(
            recover_pending(
                &reopened,
                std::slice::from_ref(&fixture.base),
                &fixture.guard
            )
            .unwrap(),
            1,
            "{checkpoint:?}"
        );
        assert_eq!(
            snapshot(&root, SnapshotBudget::default()).unwrap().entries[&fixture.auth_key()]
                .identity,
            before
        );
        let mut app = fixture.app();
        assert!(app.state());
        app.stop();
        assert!(!fixture.store.pending().unwrap());
        assert!(snapshot(&root, SnapshotBudget::default())
            .unwrap()
            .entries
            .keys()
            .all(|p| !p.contains(".everyout-validation-")));
        assert_eq!(
            recover_pending(
                &fixture.store,
                std::slice::from_ref(&fixture.base),
                &fixture.guard
            )
            .unwrap(),
            0
        );
    }
}

#[test]
fn failed_close_gate_keeps_original_quarantine_and_requires_recovery() {
    let fixture = CausalFixture::teach("");
    let mut controller = fixture.controller();
    controller.begin_trial(&fixture.guard).unwrap();
    assert!(fixture.phase(&mut controller));
    let mut app = fixture.app();
    assert!(!app.state());
    assert!(controller
        .confirm(AppOutcome::SignedOut, &fixture.store, &fixture.guard)
        .is_err());
    assert_eq!(controller.view().stage, ValidationStage::RecoveryBlocked);
    assert!(fixture.store.pending().unwrap());
    assert!(recover_pending(
        &fixture.store,
        std::slice::from_ref(&fixture.base),
        &fixture.guard
    )
    .is_err());
    assert!(fixture.store.rules().unwrap().is_empty());
    app.stop();
    drop(controller);
    recover_pending(
        &fixture.store,
        std::slice::from_ref(&fixture.base),
        &fixture.guard,
    )
    .unwrap();
    let mut app = fixture.app();
    assert!(app.state());
    app.stop();
}

#[test]
fn unknown_original_identity_in_recovery_blocks_instead_of_guessing() {
    let fixture = CausalFixture::teach("");
    let mut controller = fixture.controller();
    controller.faults.crash_at = Some(Checkpoint::Quarantined);
    controller.begin_trial(&fixture.guard).unwrap();
    let mut app = fixture.app();
    assert!(app.state());
    let thread = app.stop_soon();
    assert!(controller
        .confirm(AppOutcome::SignedIn, &fixture.store, &fixture.guard)
        .is_err());
    thread.join().unwrap();
    drop(controller);
    let mut journal = fixture
        .store
        .journals()
        .unwrap()
        .into_iter()
        .find(|j| j.stage != JournalStage::Completed)
        .unwrap();
    journal.slots[0].original.as_mut().unwrap().index ^= 1;
    fixture.store.save(&journal).unwrap();
    assert!(recover_pending(
        &fixture.store,
        std::slice::from_ref(&fixture.base),
        &fixture.guard
    )
    .is_err());
    assert!(fixture.store.pending().unwrap());
    let root = fixture.storage_root();
    assert!(root
        .path(&journal.slots[0].quarantine_relative)
        .unwrap()
        .exists()
        .unwrap());
    // Restore the test's correct ID, never reinterpret either physical object.
    journal.slots[0].original.as_mut().unwrap().index ^= 1;
    fixture.store.save(&journal).unwrap();
    recover_pending(
        &fixture.store,
        std::slice::from_ref(&fixture.base),
        &fixture.guard,
    )
    .unwrap();
}

#[test]
fn ownership_change_at_intervention_cannot_be_waived_by_outcome() {
    let fixture = CausalFixture::teach("");
    let mut controller = fixture.controller();
    controller.begin_trial(&fixture.guard).unwrap();
    fixture.guard.shared.set(true);
    let mut app = fixture.app();
    assert!(app.state());
    assert!(controller
        .confirm(AppOutcome::SignedIn, &fixture.store, &fixture.guard)
        .is_err());
    app.stop();
    assert!(fixture.store.journals().unwrap().is_empty());
    assert!(fixture.store.rules().unwrap().is_empty());
}

#[test]
fn final_contradiction_and_unclear_reversal_never_create_a_rule() {
    for unclear in [false, true] {
        let fixture = CausalFixture::teach("");
        let mut controller = fixture.controller();
        controller.begin_trial(&fixture.guard).unwrap();
        fixture.phase(&mut controller);
        fixture.phase(&mut controller);
        fixture.phase(&mut controller);
        controller.begin_trial(&fixture.guard).unwrap();
        fixture.phase(&mut controller);
        let mut app = fixture.app();
        assert!(!app.state());
        let thread = app.stop_soon();
        controller
            .confirm(
                if unclear {
                    AppOutcome::SignedOut
                } else {
                    AppOutcome::SignedIn
                },
                &fixture.store,
                &fixture.guard,
            )
            .unwrap();
        thread.join().unwrap();
        let mut app = fixture.app();
        assert!(app.state());
        let thread = app.stop_soon();
        controller
            .confirm(
                if unclear {
                    AppOutcome::Unclear
                } else {
                    AppOutcome::SignedIn
                },
                &fixture.store,
                &fixture.guard,
            )
            .unwrap();
        thread.join().unwrap();
        assert_eq!(controller.view().stage, ValidationStage::Failed);
        assert_eq!(controller.view().trials.len(), 2);
        assert!(controller
            .accept_losses(&fixture.store, &fixture.guard)
            .is_err());
        assert!(fixture.store.rules().unwrap().is_empty());
    }
}

#[test]
fn local_apply_revalidates_members_layout_ownership_and_confirmation() {
    let fixture = CausalFixture::teach("");
    let rule = fixture.validate();
    let authority = || {
        LocalLogoutAuthority::bind(
            rule.clone(),
            std::slice::from_ref(&fixture.base),
            &fixture.store,
            &fixture.guard,
        )
        .unwrap()
    };
    assert!(authority()
        .apply(false, &fixture.store, &fixture.guard)
        .is_err());
    let reviewed = authority();
    fs::create_dir(
        fixture
            .fixture
            .path()
            .join(&fixture.profile)
            .join("ChangedLayout"),
    )
    .unwrap();
    assert!(reviewed
        .apply(true, &fixture.store, &fixture.guard)
        .is_err());
    fs::remove_dir(
        fixture
            .fixture
            .path()
            .join(&fixture.profile)
            .join("ChangedLayout"),
    )
    .unwrap();
    let reviewed = authority();
    fixture.guard.shared.set(true);
    assert!(reviewed
        .apply(true, &fixture.store, &fixture.guard)
        .is_err());
    fixture.guard.shared.set(false);
    let reviewed = authority();
    let auth = fixture
        .fixture
        .path()
        .join(&fixture.profile)
        .join("Local Storage");
    fs::rename(&auth, auth.with_file_name("OriginalRetained")).unwrap();
    fs::create_dir(&auth).unwrap();
    assert!(reviewed
        .apply(true, &fixture.store, &fixture.guard)
        .is_err());
    assert!(auth
        .with_file_name("OriginalRetained")
        .join("leveldb/000123.ldb")
        .exists());
    assert!(LocalLogoutAuthority::bind(
        rule,
        std::slice::from_ref(&fixture.base),
        &fixture.store,
        &fixture.guard
    )
    .is_err());
}

#[test]
fn reparses_and_browser_wide_layouts_are_unsupported_before_first_rename() {
    let fixture = CausalFixture::teach("");
    let auth = fixture
        .fixture
        .path()
        .join(&fixture.profile)
        .join("Local Storage");
    let held = auth.with_file_name("HeldOriginal");
    fs::rename(&auth, &held).unwrap();
    std::os::windows::fs::symlink_dir(&held, &auth).unwrap();
    assert!(ValidationController::start(
        fixture.learned.clone(),
        std::slice::from_ref(&fixture.base),
        &fixture.store,
        &fixture.guard
    )
    .is_err());
    assert!(fixture.store.journals().unwrap().is_empty());
    fs::remove_dir(&auth).unwrap();
    fs::rename(&held, &auth).unwrap();
    for file in ["cookies.sqlite", "places.sqlite"] {
        fs::write(
            fixture.fixture.path().join(&fixture.profile).join(file),
            b"synthetic protected profile",
        )
        .unwrap();
    }
    assert!(ValidationController::start(
        fixture.learned.clone(),
        std::slice::from_ref(&fixture.base),
        &fixture.store,
        &fixture.guard
    )
    .is_err());
    assert!(fixture.store.journals().unwrap().is_empty());
}

#[test]
fn sqlite_family_moves_all_companions_and_restores_originally_absent_slots() {
    let fixture = CausalFixture::teach("sqlite");
    let rule = fixture.validate();
    assert_eq!(rule.scope.len(), 1);
    assert!(rule.scope[0].family.ends_with("accounts.db"));
    assert_eq!(rule.artifacts.len(), 4);
    assert!(rule
        .artifacts
        .iter()
        .find(|a| a.relative.ends_with("-journal"))
        .unwrap()
        .physical
        .is_none());
    assert!(fixture
        .store
        .journals()
        .unwrap()
        .iter()
        .all(|j| j.slots.len() == 4 && j.stage == JournalStage::Completed));
    LocalLogoutAuthority::bind(
        rule,
        std::slice::from_ref(&fixture.base),
        &fixture.store,
        &fixture.guard,
    )
    .unwrap()
    .apply(true, &fixture.store, &fixture.guard)
    .unwrap();
    let mut app = fixture.app();
    assert!(!app.state());
    app.stop();
}

#[test]
fn quarantine_restore_and_apply_succeed_when_payload_reads_are_denied_by_os() {
    use std::os::windows::fs::OpenOptionsExt;
    let fixture = CausalFixture::teach("sqlite");
    let path = fixture
        .fixture
        .path()
        .join(&fixture.profile)
        .join("accounts.db");
    let no_read = fs::OpenOptions::new()
        .read(true)
        .share_mode(4)
        .open(&path)
        .unwrap();
    assert!(fs::OpenOptions::new().read(true).open(&path).is_err());
    let rule = fixture.validate();
    LocalLogoutAuthority::bind(
        rule,
        std::slice::from_ref(&fixture.base),
        &fixture.store,
        &fixture.guard,
    )
    .unwrap()
    .apply(true, &fixture.store, &fixture.guard)
    .unwrap();
    drop(no_read);
    let mut app = fixture.app();
    assert!(!app.state());
    app.stop();
}
