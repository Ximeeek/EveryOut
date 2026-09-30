use everyout_tree_snapshot::{Snapshot, capture, compare, snapshot_path};
use std::io::{self, Read, Write};
use std::path::Path;

// Content reads are confined to explicit, validated metadata snapshot documents in diff mode.
fn load_snapshot(path: &Path) -> Result<Snapshot, Box<dyn std::error::Error>> {
    if path.extension().is_none_or(|extension| extension != "json") {
        return Err("diff inputs must be metadata .json snapshots".into());
    }
    let file = std::fs::File::open(snapshot_path(path)?)?;
    let mut bytes = Vec::new();
    file.take(64 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 64 * 1024 * 1024 {
        return Err("snapshot exceeds 64 MiB".into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let output = match args.as_slice() {
        [command, root] if command == "capture" => {
            serde_json::to_vec_pretty(&capture(Path::new(root))?)?
        }
        [command, before, after] if command == "diff" => serde_json::to_vec_pretty(&compare(
            &load_snapshot(Path::new(before))?,
            &load_snapshot(Path::new(after))?,
        )?)?,
        _ => return Err(
            "usage: everyout-tree-snapshot capture <directory> | diff <before.json> <after.json>"
                .into(),
        ),
    };
    let mut stdout = io::stdout().lock();
    stdout.write_all(&output)?;
    stdout.write_all(b"\n")?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        // OS/JSON error strings may contain private paths or document fragments.
        eprintln!(
            "tree-snapshot failed ({})",
            match error.downcast_ref::<io::Error>() {
                Some(error) => format!("{:?}", error.kind()),
                None => "invalid input or serialization failure".to_owned(),
            }
        );
        std::process::exit(1);
    }
}
