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
    assert!(root.join("fixture.marker").is_file());
    let profile = root.join("SomeVendor/RandomProfile82");
    fs::create_dir_all(profile.join("Cache")).unwrap();
    fs::create_dir_all(profile.join("Logs")).unwrap();
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
            }
            "logout" => {
                fs::remove_file(auth.join("000123.ldb")).unwrap();
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
        let mut child = Command::new(executable)
            .args(["--exact", "synthetic_application_process", "--nocapture"])
            .env("EVERYOUT_TEACH_FIXTURE", root)
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
