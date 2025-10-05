use std::{env, path::PathBuf, process::Command};
fn main() {
    // Get Postgres include directory by pg_config
    let pg_config = env::var("PG_CONFIG").unwrap_or_else(|_| "pg_config".into());
    let includedir = cmd_out(&pg_config, &["--includedir"]).trim().to_string();
    let includedir_server = cmd_out(&pg_config, &["--includedir-server"])
        .trim()
        .to_string();
    // Rebuild when shim header changes
    println!("cargo:rerun-if-changed=include/pg_oauth_shim.h");
    // Generate bindings
    let bindings = bindgen::Builder::default()
        .header("include/pg_oauth_shim.h")
        .clang_args([format!("-I{includedir}"), format!("-I{includedir_server}")])
        .allowlist_type("OAuthValidatorCallbacks")
        .allowlist_type("ValidatorModuleResult")
        .allowlist_var("PG_OAUTH_VALIDATOR_MAGIC")
        .allowlist_function("pstrdup")
        .generate()
        .expect("Unable to generate bindings");
    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("bindings.rs");
    bindings
        .write_to_file(out)
        .expect("Couldn't write bindings!");
}
fn cmd_out(bin: &str, args: &[&str]) -> String {
    let out = Command::new(bin)
        .args(args)
        .output()
        .expect("run pg_config");
    String::from_utf8(out.stdout).expect("utf8")
}