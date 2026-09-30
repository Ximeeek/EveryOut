//! Print the schema for review; runtime loading uses the bundled schema, never a URL.
fn main() {
    println!(
        "{}",
        serde_json::to_string_pretty(&everyout_providers::manifest::manifest_schema()).unwrap()
    );
}
