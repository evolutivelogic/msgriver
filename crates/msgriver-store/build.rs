use std::{env, fs, path::PathBuf};

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let contract = manifest.join("../../tasks/0010-v2-ddl-contract.md");
    println!("cargo:rerun-if-changed={}", contract.display());
    let document = fs::read_to_string(&contract).expect("read v2 DDL contract");
    let start = document.find("```sql\n").expect("v2 SQL fence") + "```sql\n".len();
    let end = document[start..].find("\n```").expect("v2 SQL fence end") + start;
    let output = PathBuf::from(env::var("OUT_DIR").expect("output directory"))
        .join("migration_v2_selected_state.sql");
    fs::write(output, &document[start..end]).expect("write embedded v2 SQL");
}
