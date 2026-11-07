//! Link settings of the shipped library that the manifest has no key for.
//!
//! **`-headerpad_max_install_names` on Apple targets.** `dart run`, `dart test`
//! and `flutter test` copy the dylib into the consuming project and rewrite its
//! install name to the copy's absolute path (`install_name_tool -id`). The
//! linker leaves only the room the build machine's own path needed, so that
//! rewrite fails once the copy's path is a little longer — about 180 characters
//! with the libraries the release workflow builds — with "larger updated load
//! commands do not fit". This flag reserves room for every path in the header
//! to grow to `MAXPATHLEN`. Flutter app builds never hit it: they install the
//! library as a framework under a short `@rpath/` name.
//!
//! A build script and not `rustflags` in `.cargo/config.toml`, because the
//! latter is not reliably seen: `make build` runs cargo from the repository
//! root, where `rust/.cargo/` is not read, and a `RUSTFLAGS` in the environment
//! replaces config rustflags wholesale. `rustc-link-arg-cdylib` reaches the
//! cdylib's link either way, and no other artefact.
//!
//! `make verify-release-artifacts` refuses a release whose Apple libraries
//! leave less room than that (`MIN_INSTALL_NAME_ROOM`), so a lost flag fails
//! the release instead of a consumer's build.
//!
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
    if is_apple_target {
        println!("cargo::rustc-link-arg-cdylib=-Wl,-headerpad_max_install_names");
    }
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
