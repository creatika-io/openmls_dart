//! Refuses an Apple build whose SQLCipher would link a system libcrypto.
//!
//! On Apple targets libsqlite3-sys builds SQLCipher on CommonCrypto unless an
//! OpenSSL location is set in the environment, in which case it links that
//! OpenSSL's `libcrypto` dynamically instead, without a word.

const OPENSSL_LOCATION_VARIABLES: [&str; 3] =
    ["OPENSSL_DIR", "OPENSSL_LIB_DIR", "OPENSSL_INCLUDE_DIR"];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let target = std::env::var("TARGET").expect("cargo sets TARGET");
    let target_prefix = target.to_uppercase().replace('-', "_");
    let variables: Vec<String> = OPENSSL_LOCATION_VARIABLES
        .iter()
        .flat_map(|name| [name.to_string(), format!("{target_prefix}_{name}")])
        .collect();
    for variable in &variables {
        println!("cargo:rerun-if-env-changed={variable}");
    }

    let is_apple_target = std::env::var("CARGO_CFG_TARGET_VENDOR").as_deref() == Ok("apple");
    let set_variables: Vec<&str> = variables
        .iter()
        .filter(|variable| std::env::var_os(variable).is_some())
        .map(String::as_str)
        .collect();
    if is_apple_target && !set_variables.is_empty() {
        panic!(
            "{} set for {target}: SQLCipher would link that OpenSSL's libcrypto instead of \
             CommonCrypto. Unset it for this build.",
            set_variables.join(", ")
        );
    }
}
