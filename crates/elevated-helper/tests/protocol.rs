use everyout_core_model::AccountMode;
use everyout_elevated_helper::{protocol::*, *};
use std::{sync::mpsc, thread, time::Duration};

fn peer() -> Peer {
    Peer {
        sid: "S-1-5-21-100-200-300-1001".into(),
        logon: (17, 0),
        session: 1,
        pid: 42,
    }
}
fn nonce() -> String {
    "a".repeat(64)
}
fn request(sequence: u64, command: Command) -> Request {
    Request {
        version: VERSION,
        run: nonce(),
        sequence,
        nonce: if sequence == 0 {
            nonce()
        } else {
            String::new()
        },
        command,
    }
}
fn authenticated() -> Session {
    let mut session = Session::new(peer(), nonce()).unwrap();
    let response = session
        .receive(
            &encode(&request(0, Command::Report)).unwrap(),
            &peer(),
            Duration::ZERO,
            true,
        )
        .unwrap();
    assert_eq!(response.status, Status::Authenticated);
    session
}
#[test]
fn in_process_fake_client_and_helper_exchange_and_finish() {
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let (answers, output) = mpsc::channel();
    let helper = thread::spawn(move || {
        let mut session = Session::new(peer(), nonce()).unwrap();
        for frame in rx {
            let response = session
                .receive(&frame, &peer(), Duration::ZERO, true)
                .unwrap();
            let done = response.status == Status::Finished;
            answers.send(encode(&response).unwrap()).unwrap();
            if done {
                return;
            }
        }
    });
    for (sequence, command, status) in [
        (0, Command::Report, Status::Authenticated),
        (1, Command::EnumerateProfiles, Status::ScopeUnavailable),
        (2, Command::Finish, Status::Finished),
    ] {
        tx.send(encode(&request(sequence, command)).unwrap())
            .unwrap();
        let response: Response = serde_json::from_slice(&output.recv().unwrap()).unwrap();
        assert_eq!(response.status, status);
        assert_eq!(response.sequence, sequence);
    }
    helper.join().unwrap();
}
#[test]
fn handshake_binds_nonce_sid_logon_session_pid_version_and_run() {
    let correct = request(0, Command::Report);
    for variant in 0..8 {
        let mut p = peer();
        let mut r = request(0, Command::Report);
        match variant {
            0 => r.nonce = "b".repeat(64),
            1 => p.sid = "S-1-5-21-100-200-300-1002".into(),
            2 => p.logon.0 += 1,
            3 => p.session += 1,
            4 => p.pid += 1,
            5 => r.version += 1,
            6 => r.run = "b".repeat(64),
            _ => r.sequence += 1,
        }
        let mut session = Session::new(peer(), nonce()).unwrap();
        assert_eq!(
            session
                .receive(&encode(&r).unwrap(), &p, Duration::ZERO, true)
                .unwrap_err(),
            Status::Rejected
        );
        // Rejected sessions cannot be recovered with a correct handshake.
        assert!(session
            .receive(&encode(&correct).unwrap(), &peer(), Duration::ZERO, true)
            .is_err());
    }
}
#[test]
fn unknown_commands_fields_and_path_injection_close_the_session() {
    let base = serde_json::to_value(request(1, Command::Report)).unwrap();
    let mut cases = Vec::new();
    for command in ["shell", "delete-path", "mount-hive"] {
        let mut value = base.clone();
        value["command"]["command"] = command.into();
        cases.push(value);
    }
    for field in ["path", "registry", "executable", "sid", "payload"] {
        let mut value = base.clone();
        value[field] = r"C:\Users\foreign\Cookies".into();
        cases.push(value);
    }
    let selection = Selection {
        provider_id: "chrome".into(),
        revision: 1,
        account_id: "account-b".into(),
    };
    let mut nested = serde_json::to_value(request(
        1,
        Command::Plan {
            selections: vec![selection],
        },
    ))
    .unwrap();
    nested["command"]["selections"][0]["path"] = r"C:\outside".into();
    cases.push(nested);
    for value in cases {
        let mut session = authenticated();
        assert!(session
            .receive(
                &serde_json::to_vec(&value).unwrap(),
                &peer(),
                Duration::ZERO,
                true
            )
            .is_err());
        assert!(session.expired(Duration::ZERO, true));
    }
    for path in [
        r"C:\outside",
        "../escape",
        r"\\server\share",
        "%APPDATA%",
        "x:stream",
    ] {
        for inject_provider in [false, true] {
            let mut session = authenticated();
            let selection = Selection {
                provider_id: if inject_provider {
                    path.into()
                } else {
                    "chrome".into()
                },
                revision: 1,
                account_id: if inject_provider {
                    "account-b".into()
                } else {
                    path.into()
                },
            };
            assert!(session
                .receive(
                    &encode(&request(
                        1,
                        Command::Plan {
                            selections: vec![selection]
                        }
                    ))
                    .unwrap(),
                    &peer(),
                    Duration::ZERO,
                    true
                )
                .is_err());
        }
    }
}
#[test]
fn replay_oversize_and_empty_messages_are_rejected() {
    let mut session = authenticated();
    assert!(session
        .receive(
            &encode(&request(0, Command::Report)).unwrap(),
            &peer(),
            Duration::ZERO,
            true
        )
        .is_err());
    for frame in [vec![], vec![b' '; MAX_FRAME + 1], b"{}".to_vec()] {
        assert!(authenticated()
            .receive(&frame, &peer(), Duration::ZERO, true)
            .is_err());
    }
    let mut request = request(1, Command::Report);
    request.nonce = nonce();
    assert!(authenticated()
        .receive(&encode(&request).unwrap(), &peer(), Duration::ZERO, true)
        .is_err());
}

#[test]
fn complete_payload_validation_rejects_hidden_paths_and_duplicate_fields() {
    let selections = vec![
        Selection {
            provider_id: "unknown-provider".into(),
            revision: 1,
            account_id: "account-b".into(),
        },
        Selection {
            provider_id: "chrome".into(),
            revision: 2,
            account_id: "../foreign".into(),
        },
    ];
    assert!(authenticated()
        .receive(
            &encode(&request(1, Command::Plan { selections })).unwrap(),
            &peer(),
            Duration::ZERO,
            true
        )
        .is_err());
    let frame = String::from_utf8(encode(&request(1, Command::Report)).unwrap()).unwrap();
    let duplicate = frame.replacen("\"version\":1", "\"version\":1,\"version\":1", 1);
    assert!(authenticated()
        .receive(duplicate.as_bytes(), &peer(), Duration::ZERO, true)
        .is_err());
    let mut value = serde_json::to_value(request(
        1,
        Command::Execute {
            plan_id: "invented-plan".into(),
            dry_run: true,
        },
    ))
    .unwrap();
    value["command"]["path"] = r"C:\outside".into();
    assert!(authenticated()
        .receive(
            &serde_json::to_vec(&value).unwrap(),
            &peer(),
            Duration::ZERO,
            true
        )
        .is_err());
}
#[test]
fn parent_loss_idle_timeout_and_absolute_lifetime_end_helper_loop() {
    for (now, alive) in [
        (Duration::ZERO, false),
        (IDLE_TIMEOUT, true),
        (MAX_LIFETIME, true),
    ] {
        let helper = thread::spawn(move || {
            let mut session = authenticated();
            assert!(session.expired(now, alive));
            assert!(session
                .receive(
                    &encode(&request(1, Command::Report)).unwrap(),
                    &peer(),
                    now,
                    alive
                )
                .is_err());
        });
        helper.join().unwrap();
    }
    let mut session = authenticated();
    for seconds in (10..300).step_by(10) {
        session
            .receive(
                &encode(&request(seconds / 10, Command::Report)).unwrap(),
                &peer(),
                Duration::from_secs(seconds),
                true,
            )
            .unwrap();
    }
    assert!(session.expired(MAX_LIFETIME, true));
}
#[test]
fn independent_catalog_validation_and_missing_scope_prevent_effects() {
    for (id, revision, expected) in [
        ("chrome", 2, Status::CandidateBlocked),
        ("chrome", u64::MAX, Status::StaleRevision),
        ("unknown-provider", 1, Status::UnknownProvider),
    ] {
        let mut session = authenticated();
        let selection = Selection {
            provider_id: id.into(),
            revision,
            account_id: "account-b".into(),
        };
        let response = session
            .receive(
                &encode(&request(
                    1,
                    Command::Plan {
                        selections: vec![selection],
                    },
                ))
                .unwrap(),
                &peer(),
                Duration::ZERO,
                true,
            )
            .unwrap();
        assert_eq!(response.status, expected);
        for (sequence, command) in [
            (
                2,
                Command::Execute {
                    plan_id: "invented-plan".into(),
                    dry_run: true,
                },
            ),
            (
                3,
                Command::Execute {
                    plan_id: "invented-plan".into(),
                    dry_run: false,
                },
            ),
            (
                4,
                Command::CloseProcesses {
                    plan_id: "invented-plan".into(),
                },
            ),
        ] {
            assert_eq!(
                session
                    .receive(
                        &encode(&request(sequence, command)).unwrap(),
                        &peer(),
                        Duration::ZERO,
                        true
                    )
                    .unwrap()
                    .status,
                Status::ScopeUnavailable
            );
        }
    }
}
#[test]
fn current_mode_and_remembered_preference_never_call_launcher() {
    for (mode, needed) in [
        (AccountMode::Current, false),
        (AccountMode::Current, true),
        (AccountMode::AllAccounts, false),
    ] {
        let outcome: LaunchOutcome<()> =
            launch_on_demand(mode, needed, || panic!("elevation must not be called"));
        assert!(matches!(outcome, LaunchOutcome::CurrentAccount));
    }
    let mut calls = 0;
    assert!(matches!(
        launch_on_demand(AccountMode::AllAccounts, true, || {
            calls += 1;
            Ok(())
        }),
        LaunchOutcome::Elevated(())
    ));
    assert_eq!(calls, 1);
}
#[test]
fn declined_uac_and_launch_failures_produce_distinct_current_scope_fallback() {
    for reason in [
        LaunchFailure::UacDeclined,
        LaunchFailure::StartFailed,
        LaunchFailure::AuthenticationFailed,
        LaunchFailure::Timeout,
    ] {
        let result: LaunchOutcome<()> =
            launch_on_demand(AccountMode::AllAccounts, true, || Err(reason));
        let LaunchOutcome::Fallback(fallback) = result else {
            panic!("fallback expected")
        };
        assert_eq!(fallback.reason, reason);
        assert_eq!(fallback.effective_mode, AccountMode::Current);
        assert_eq!(fallback.saved_mode, AccountMode::Current);
        assert!(fallback.requires_fresh_review);
    }
}

#[test]
fn account_backend_is_dispatched_only_after_authentication_and_payload_validation() {
    use std::{cell::Cell, collections::BTreeMap, rc::Rc};
    struct Recording(Rc<Cell<usize>>);
    impl AccountBackend for Recording {
        fn dispatch(
            &mut self,
            _command: &Command,
            _catalog: &BTreeMap<String, everyout_providers::Manifest>,
            _run: &str,
        ) -> BackendReply {
            self.0.set(self.0.get() + 1);
            BackendReply::status(Status::ProfilesReady)
        }
    }
    let calls = Rc::new(Cell::new(0));
    let mut session = authenticated().with_backend(Box::new(Recording(calls.clone())));
    let response = session
        .receive(
            &encode(&request(1, Command::EnumerateProfiles)).unwrap(),
            &peer(),
            Duration::ZERO,
            true,
        )
        .unwrap();
    assert_eq!(response.status, Status::ProfilesReady);
    assert_eq!(calls.get(), 1);
    let injected = Command::Review {
        plan_id: "plan-a".into(),
        digest: "a".repeat(64),
        accounts: vec![everyout_engine::accounts::AccountConsent {
            account: "../foreign".into(),
            ..Default::default()
        }],
    };
    assert!(session
        .receive(
            &encode(&request(2, injected)).unwrap(),
            &peer(),
            Duration::ZERO,
            true
        )
        .is_err());
    assert_eq!(calls.get(), 1);
    let calls = Rc::new(Cell::new(0));
    let mut session = Session::new(peer(), nonce())
        .unwrap()
        .with_backend(Box::new(Recording(calls.clone())));
    assert!(session
        .receive(
            &encode(&request(0, Command::EnumerateProfiles)).unwrap(),
            &peer(),
            Duration::ZERO,
            true
        )
        .is_err());
    assert_eq!(calls.get(), 0);
}
