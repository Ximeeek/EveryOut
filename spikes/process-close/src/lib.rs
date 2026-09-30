#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Method {
    RestartManager,
    WmClose,
    Force,
}
#[derive(Debug)]
pub struct Options {
    pub pid: u32,
    pub image: String,
    pub method: Method,
    pub hard_kill: bool,
}
pub fn parse(args: &[String]) -> Result<Options, &'static str> {
    if !args
        .iter()
        .any(|a| a == "--i-understand-this-closes-processes")
    {
        return Err("confirmation required");
    }
    let (mut pid, mut image, mut method, mut confirmed, mut hard_kill) =
        (None, None, None, false, false);
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--i-understand-this-closes-processes" if !confirmed => confirmed = true,
            "--hard-kill-after-2s" if !hard_kill => hard_kill = true,
            "--pid" if pid.is_none() => {
                i += 1;
                pid = Some(
                    args.get(i)
                        .ok_or("missing pid")?
                        .parse::<u32>()
                        .map_err(|_| "invalid pid")?,
                );
            }
            "--image" if image.is_none() => {
                i += 1;
                image = Some(args.get(i).ok_or("missing image")?.clone());
            }
            "--method" if method.is_none() => {
                i += 1;
                method = Some(match args.get(i).map(String::as_str) {
                    Some("restart-manager") => Method::RestartManager,
                    Some("wm-close") => Method::WmClose,
                    Some("force") => Method::Force,
                    _ => return Err("invalid method"),
                });
            }
            _ => return Err("unknown or duplicate argument"),
        }
        i += 1;
    }
    let pid = pid
        .filter(|p| *p != 0)
        .ok_or("explicit nonzero pid required")?;
    let image = image.ok_or("explicit image required")?;
    if !image.to_ascii_lowercase().ends_with(".exe")
        || image.len() <= 4
        || image
            .chars()
            .any(|c| c.is_control() || ['/', '\\', ':', '*', '?', '"', '<', '>', '|'].contains(&c))
    {
        return Err("image must be exact executable basename");
    }
    let method = method.ok_or("method required")?;
    if hard_kill && method != Method::WmClose {
        return Err(
            "two-second escalation supported only with wm-close; Restart Manager call is synchronous",
        );
    }
    Ok(Options {
        pid,
        image,
        method,
        hard_kill,
    })
}
