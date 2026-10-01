#[cfg(windows)]
mod windows {
    use std::os::windows::process::CommandExt;
    use std::{
        io::{BufRead, BufReader, Write},
        process::{Child, Command, Stdio},
        time::{Duration, Instant},
    };
    use windows_sys::Win32::{
        Foundation::{HWND, LPARAM, LRESULT, WPARAM},
        System::LibraryLoader::GetModuleHandleW,
        UI::WindowsAndMessaging::*,
    };
    unsafe extern "system" fn window(
        hwnd: HWND,
        message: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        if message == WM_CLOSE || (message == WM_ENDSESSION && wparam != 0) {
            if std::env::var_os("EVERYOUT_DUMMY_REFUSE").is_none() {
                unsafe {
                    PostQuitMessage(0);
                }
            }
            return 0;
        }
        unsafe { DefWindowProcW(hwnd, message, wparam, lparam) }
    }
    #[test]
    #[ignore = "subprocess fixture only; parent explicitly invokes this test"]
    fn dummy_process() {
        assert!(std::env::var_os("EVERYOUT_DUMMY_PROCESS").is_some());
        if std::env::var_os("EVERYOUT_DUMMY_NO_WINDOW").is_some() {
            println!("READY");
            std::io::stdout().flush().unwrap();
            loop {
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        let class: Vec<u16> = "EveryOutLabDummy".encode_utf16().chain([0]).collect();
        unsafe {
            let instance = GetModuleHandleW(std::ptr::null());
            let wc = WNDCLASSW {
                lpfnWndProc: Some(window),
                hInstance: instance,
                lpszClassName: class.as_ptr(),
                ..Default::default()
            };
            assert_ne!(RegisterClassW(&wc), 0);
            let hwnd = CreateWindowExW(
                0,
                class.as_ptr(),
                class.as_ptr(),
                WS_OVERLAPPEDWINDOW,
                0,
                0,
                100,
                100,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                instance,
                std::ptr::null(),
            );
            assert!(!hwnd.is_null());

            println!("READY");
            std::io::stdout().flush().unwrap();
            let mut message = MSG::default();
            while GetMessageW(&mut message, std::ptr::null_mut(), 0, 0) > 0 {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
    }
    struct Dummy(Child);
    impl Drop for Dummy {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    fn spawn(refuse: bool) -> Dummy {
        spawn_mode(refuse, false)
    }
    fn spawn_mode(refuse: bool, no_window: bool) -> Dummy {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--ignored",
                "--exact",
                "windows::dummy_process",
                "--nocapture",
            ])
            .env("EVERYOUT_DUMMY_PROCESS", "1")
            .stdout(Stdio::piped())
            .creation_flags(0x08000000);
        if refuse {
            command.env("EVERYOUT_DUMMY_REFUSE", "1");
        }
        if no_window {
            command.env("EVERYOUT_DUMMY_NO_WINDOW", "1");
        }
        let mut dummy = Dummy(command.spawn().unwrap());
        let output = dummy.0.stdout.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut reader = BufReader::new(output);
            for line in (&mut reader).lines() {
                if line.unwrap().contains("READY") {
                    let _ = tx.send(reader.into_inner());
                    break;
                }
            }
        });
        dummy.0.stdout = Some(
            rx.recv_timeout(Duration::from_secs(10))
                .expect("dummy readiness deadline"),
        );
        reader.join().unwrap();
        dummy
    }
    use everyout_platform_windows::process::*;
    fn observed(dummy: &Dummy) -> Process {
        let mut inventory = enumerate_current_user().unwrap();
        let index = inventory
            .processes
            .iter()
            .position(|p| p.pid() == dummy.0.id())
            .expect("owned dummy in inventory");
        let p = inventory.processes.swap_remove(index);
        assert!(p.image_path().is_absolute());
        assert_eq!(p.image_path(), std::env::current_exe().unwrap());
        assert!(p.creation_ticks() > 0);
        p
    }
    fn status(report: &ProcessCloseReport, expected: ProcessCloseStatus) {
        assert_eq!(report.results.len(), 1);
        assert_eq!(
            report.results[0].status, expected,
            "{:?}",
            report.results[0]
        );
        assert_eq!(report.results[0].error, None);
    }
    #[test]
    fn graceful_close_preserves_same_image_sibling() {
        let mut dummy = spawn(false);
        let mut sibling = spawn(false);
        let p = observed(&dummy);
        let names = vec![p.image_name().to_string_lossy().to_uppercase()];
        assert!(p.matches(&names, &[]));
        assert!(p.matches(&[], &[p.image_path().to_owned()]));
        assert!(!p.matches(&[], &[]));
        assert!(!p.matches(&["wrong.exe".into()], &[]));
        assert!(!p.matches(&names, &[p.image_path().with_file_name("wrong.exe")]));
        let report = close_processes(&[&p], ProcessClosePolicy::Ask, false);
        status(&report, ProcessCloseStatus::ClosedGracefully);
        assert!(report.remaining.is_empty());
        assert!(report.results[0].windows_requested >= 1);
        assert!(report.results[0].force_after.is_none());
        assert!(dummy.0.wait().unwrap().success());
        assert!(sibling.0.try_wait().unwrap().is_none());
    }
    #[test]
    fn ask_returns_refusing_process_and_force_waits_two_seconds() {
        let mut dummy = spawn(true);
        let mut sibling = spawn(true);
        let p = observed(&dummy);
        let report = close_processes(&[&p], ProcessClosePolicy::Ask, false);
        status(&report, ProcessCloseStatus::StillRunning);
        assert_eq!(report.remaining, [0]);
        assert!(report.results[0].force_after.is_none());
        assert!(dummy.0.try_wait().unwrap().is_none());
        let start = Instant::now();
        let report = close_processes(&[&p], ProcessClosePolicy::HardKillAfter2s, false);
        status(&report, ProcessCloseStatus::Killed);
        assert!(report.remaining.is_empty());
        let force_after = report.results[0].force_after.unwrap();
        assert!(force_after >= Duration::from_secs(2));
        assert!(
            force_after < Duration::from_secs(3),
            "force scheduling: {force_after:?}"
        );
        assert!(start.elapsed() >= Duration::from_secs(2));
        assert!(!dummy.0.wait().unwrap().success());
        assert!(sibling.0.try_wait().unwrap().is_none());
    }
    #[test]
    fn dry_run_sends_no_close_request_even_with_force_policy() {
        let mut dummy = spawn(false);
        let p = observed(&dummy);
        for policy in [ProcessClosePolicy::Ask, ProcessClosePolicy::HardKillAfter2s] {
            let report = close_processes(&[&p], policy, true);
            status(&report, ProcessCloseStatus::WouldClose);
            assert_eq!(report.remaining, [0]);
            assert_eq!(report.results[0].windows_requested, 0);
            assert!(report.results[0].force_after.is_none());
        }
        std::thread::sleep(Duration::from_millis(100));
        assert!(dummy.0.try_wait().unwrap().is_none());
    }
    #[test]
    fn exited_selection_never_substitutes_same_image_process() {
        let mut dummy = spawn(true);
        let mut sibling = spawn(true);
        let p = observed(&dummy);
        dummy.0.kill().unwrap();
        dummy.0.wait().unwrap();
        let report = close_processes(&[&p], ProcessClosePolicy::HardKillAfter2s, false);
        assert!(matches!(
            report.results[0].status,
            ProcessCloseStatus::ClosedGracefully | ProcessCloseStatus::Failed
        ));
        assert!(report.results[0].force_after.is_none());
        assert!(sibling.0.try_wait().unwrap().is_none());
    }
    #[test]
    fn windowless_process_returns_to_caller_under_ask() {
        let mut dummy = spawn_mode(false, true);
        let p = observed(&dummy);
        let report = close_processes(&[&p], ProcessClosePolicy::Ask, false);
        status(&report, ProcessCloseStatus::StillRunning);
        assert_eq!(report.results[0].windows_requested, 0);
        assert_eq!(report.remaining, [0]);
        assert!(dummy.0.try_wait().unwrap().is_none());
        let report = close_processes(&[&p], ProcessClosePolicy::HardKillAfter2s, false);
        status(&report, ProcessCloseStatus::Killed);
        assert!(report.results[0].force_after.unwrap() >= Duration::from_secs(2));
    }
    #[test]
    fn duplicate_selection_fails_without_additional_requests() {
        let mut dummy = spawn(false);
        let p = observed(&dummy);
        let report = close_processes(&[&p, &p], ProcessClosePolicy::Ask, true);
        assert_eq!(report.results[0].status, ProcessCloseStatus::WouldClose);
        assert_eq!(report.results[1].status, ProcessCloseStatus::Failed);
        assert_eq!(
            report.results[1].error.unwrap().kind,
            everyout_core_model::ErrorKind::ScopeViolation
        );
        assert!(dummy.0.try_wait().unwrap().is_none());
    }
}
