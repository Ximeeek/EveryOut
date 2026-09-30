use everyout_process_close::{Method, parse};
fn args(text: &str) -> Vec<String> {
    text.split_whitespace().map(str::to_owned).collect()
}
#[test]
fn confirmation_and_exact_target_are_mandatory() {
    let valid =
        "--pid 123 --image dummy.exe --method wm-close --i-understand-this-closes-processes";
    assert_eq!(parse(&args(valid)).unwrap().method, Method::WmClose);
    for invalid in [
        "--pid 123 --image dummy.exe --method force",
        "--i-understand-this-closes-processes",
        "--pid 0 --image dummy.exe --method force --i-understand-this-closes-processes",
        "--pid 123 --image *.exe --method force --i-understand-this-closes-processes",
        "--pid 123 --image C:/dummy.exe --method force --i-understand-this-closes-processes",
    ] {
        assert!(parse(&args(invalid)).is_err());
    }
    assert!(parse(&args(&format!("{valid} --pid 456"))).is_err());
    assert!(
        parse(&args(&format!("{valid} --hard-kill-after-2s")))
            .unwrap()
            .hard_kill
    );
    assert!(
        parse(&args(&format!(
            "{} --hard-kill-after-2s",
            valid.replace("wm-close", "restart-manager")
        )))
        .is_err()
    );
}
#[test]
fn cli_refuses_before_any_process_api_without_confirmation() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_everyout-process-close"))
        .args(["--pid", "123", "--image", "dummy.exe", "--method", "force"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("confirmation required"));
}

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
        System::{LibraryLoader::GetModuleHandleW, Recovery::RegisterApplicationRestart},
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
            assert_eq!(RegisterApplicationRestart(std::ptr::null(), 0), 0);
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
        let mut child = command.spawn().unwrap();
        let mut ready = false;
        let mut reader = BufReader::new(child.stdout.take().unwrap());
        for line in (&mut reader).lines() {
            if line.unwrap().contains("READY") {
                ready = true;
                break;
            }
        }
        child.stdout = Some(reader.into_inner());
        assert!(ready);
        Dummy(child)
    }
    fn invoke(dummy: &Dummy, method: &str, image: &str, hard: bool) -> std::process::Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_everyout-process-close"));
        command.args([
            "--pid",
            &dummy.0.id().to_string(),
            "--image",
            image,
            "--method",
            method,
            "--i-understand-this-closes-processes",
        ]);
        if hard {
            command.arg("--hard-kill-after-2s");
        }
        command.output().unwrap()
    }
    #[test]
    fn closes_only_spawned_dummy_and_enforces_image_identity() {
        let image = std::env::current_exe()
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        for method in ["wm-close", "force", "restart-manager"] {
            let mut dummy = spawn(false);
            let mut sibling = spawn(false);
            let refused = invoke(&dummy, method, "wrong-image.exe", false);
            assert_eq!(refused.status.code(), Some(1));
            assert!(dummy.0.try_wait().unwrap().is_none());
            let output = invoke(&dummy, method, &image, false);
            assert!(
                output.status.success(),
                "{method}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(report["outcome"], "exited");
            assert_eq!(report["escalated"], false);
            assert!(sibling.0.try_wait().unwrap().is_none());
            let deadline = Instant::now() + Duration::from_secs(2);
            while dummy.0.try_wait().unwrap().is_none() {
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        let mut dummy = spawn(true);
        let declined = invoke(&dummy, "wm-close", &image, false);
        assert_eq!(declined.status.code(), Some(2));
        assert!(dummy.0.try_wait().unwrap().is_none());
        let declined_report: serde_json::Value = serde_json::from_slice(&declined.stdout).unwrap();
        assert_eq!(declined_report["escalated"], false);
        let start = Instant::now();
        let output = invoke(&dummy, "wm-close", &image, true);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["escalated"], true);
        assert!(report["escalation_ms"].as_u64().unwrap() >= 2000);
        assert!(report["grace_ms_before_force"].as_u64().unwrap() >= 2000);
        assert!(start.elapsed() >= Duration::from_secs(2));
    }
}
