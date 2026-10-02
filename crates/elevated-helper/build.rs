use std::{env, fs, path::Path};

fn collect(path: &Path, files: &mut Vec<std::path::PathBuf>) {
    for entry in fs::read_dir(path).expect("bundled catalog directory") {
        let path = entry.expect("catalog entry").path();
        if path.is_dir() {
            collect(&path, files);
        } else if path.extension().is_some_and(|e| e == "json") {
            files.push(path.canonicalize().expect("catalog path"));
        }
    }
}
fn main() {
    let mut files = Vec::new();
    for directory in ["browsers", "apps", "windows-dev"] {
        let root = Path::new("../../catalog").join(directory);
        println!("cargo:rerun-if-changed={}", root.display());
        collect(&root, &mut files);
    }
    files.sort();
    let mut output = String::from("const BUNDLED: &[&str] = &[\n");
    for path in files {
        output.push_str(&format!(
            "include_str!({:?}),\n",
            path.to_str().expect("path")
        ));
    }
    output.push_str("];\n");
    fs::write(
        Path::new(&env::var_os("OUT_DIR").expect("out dir")).join("catalog.rs"),
        output,
    )
    .expect("generated catalog index");
}
