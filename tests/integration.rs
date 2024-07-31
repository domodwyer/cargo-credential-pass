mod common;

use assert_cmd::Command;
use common::{gpg::GpgHandle, pass::PassHandle};
use predicates::prelude::predicate;

#[test]
fn test_token_lifecycle_with_name() {
    let gpg = GpgHandle::default();
    let pass = PassHandle::new(&gpg);

    let hello = r#"{"v":[1]}"#;
    let login_request = r#"{"v": 1,"registry": {"index-url":"sparse+https://itsallbroken.com/rust-lang/crates.io-index","name":"crates-io"},"kind": "login","token": "platanos","args": []}"#;
    let login_response = r#"{"Ok":{"kind":"login"}}"#;

    //
    // Login and validate the token is returned
    //

    run_plugin(
        format!("{login_request}\n"),
        format!("{hello}\n{login_response}\n"),
        &pass,
        &gpg,
    );

    let read_request = r#"{"v": 1,"registry": {"index-url":"sparse+https://itsallbroken.com/rust-lang/crates.io-index","name":"crates-io"},"kind": "get","operation": "read","args": []}"#;
    let token_response = r#"{"Ok":{"kind":"get","token":"platanos","cache":"session","operation_independent":true}}"#;

    run_plugin(
        format!("{read_request}\n"),
        format!("{hello}\n{token_response}\n"),
        &pass,
        &gpg,
    );

    //
    // Update the token
    //

    let login_request = r#"{"v": 1,"registry": {"index-url":"sparse+https://itsallbroken.com/rust-lang/crates.io-index","name":"crates-io"},"kind": "login","token": "bananas","args": []}"#;
    let login_response = r#"{"Ok":{"kind":"login"}}"#;

    run_plugin(
        format!("{login_request}\n"),
        format!("{hello}\n{login_response}\n"),
        &pass,
        &gpg,
    );

    let read_request = r#"{"v": 1,"registry": {"index-url":"sparse+https://itsallbroken.com/rust-lang/crates.io-index","name":"crates-io"},"kind": "get","operation": "read","args": []}"#;
    let token_response =
        r#"{"Ok":{"kind":"get","token":"bananas","cache":"session","operation_independent":true}}"#;

    run_plugin(
        format!("{read_request}\n"),
        format!("{hello}\n{token_response}\n"),
        &pass,
        &gpg,
    );

    //
    // Read for a publish request
    //

    let publish_request = r#"{"v":1,"kind":"get","operation":"publish","name":"crates-io","vers":"0.1.0","cksum":"...","registry":{"index-url":"sparse+https://itsallbroken.com/rust-lang/crates.io-index","name":"crates-io"},"args": []}"#;

    run_plugin(
        format!("{publish_request}\n"),
        format!("{hello}\n{token_response}\n"),
        &pass,
        &gpg,
    );

    //
    // Logout and validate the token is no longer readable.
    //

    let logout_request = r#"{"v":1,"registry":{"index-url":"sparse+https://itsallbroken.com/rust-lang/crates.io-index","name":"crates-io"},"kind":"logout","args":[]}"#;
    let logout_response = r#"{"Ok":{"kind":"logout"}}"#;

    run_plugin(
        format!("{logout_request}\n"),
        format!("{hello}\n{logout_response}\n"),
        &pass,
        &gpg,
    );

    let read_err_response = "{\"Err\":{\"kind\":\"other\",\"message\":\"pass exited with a non-zero status code (stdout=\'\', stderr=\'Error: cargo-registry/crates-io.token is not in the password store.\')\",\"caused-by\":[]}}";

    run_plugin(
        format!("{read_request}\n"),
        format!("{hello}\n{read_err_response}\n"),
        &pass,
        &gpg,
    );
}

#[test]
fn test_token_lifecycle_without_name() {
    let gpg = GpgHandle::default();
    let pass = PassHandle::new(&gpg);

    let hello = r#"{"v":[1]}"#;
    let login_request = r#"{"v": 1,"registry": {"index-url":"sparse+https://itsallbroken.com/rust-lang/crates.io-index"},"kind": "login","token": "bananas","args": []}"#;
    let login_response = r#"{"Ok":{"kind":"login"}}"#;

    run_plugin(
        format!("{login_request}\n"),
        format!("{hello}\n{login_response}\n"),
        &pass,
        &gpg,
    );

    let read_request = r#"{"v": 1,"registry": {"index-url":"sparse+https://itsallbroken.com/rust-lang/crates.io-index"},"kind": "get","operation": "read","args": []}"#;
    let token_response =
        r#"{"Ok":{"kind":"get","token":"bananas","cache":"session","operation_independent":true}}"#;

    run_plugin(
        format!("{read_request}\n"),
        format!("{hello}\n{token_response}\n"),
        &pass,
        &gpg,
    );

    let publish_request = r#"{"v":1,"kind":"get","operation":"publish","name":"","vers":"0.1.0","cksum":"...","registry":{"index-url":"sparse+https://itsallbroken.com/rust-lang/crates.io-index"},"args": []}"#;

    run_plugin(
        format!("{publish_request}\n"),
        format!("{hello}\n{token_response}\n"),
        &pass,
        &gpg,
    );

    let logout_request = r#"{"v":1,"registry":{"index-url":"sparse+https://itsallbroken.com/rust-lang/crates.io-index"},"kind":"logout","args":[]}"#;
    let logout_response = r#"{"Ok":{"kind":"logout"}}"#;

    run_plugin(
        format!("{logout_request}\n"),
        format!("{hello}\n{logout_response}\n"),
        &pass,
        &gpg,
    );

    let read_err_response = "{\"Err\":{\"kind\":\"other\",\"message\":\"pass exited with a non-zero status code (stdout=\'\', stderr=\'Error: cargo-registry/https___itsallbroken_com_rust_lang_crates_io_index.token is not in the password store.\')\",\"caused-by\":[]}}";

    run_plugin(
        format!("{read_request}\n"),
        format!("{hello}\n{read_err_response}\n"),
        &pass,
        &gpg,
    );
}

fn run_plugin(stdin: String, want_stdout: String, pass: &PassHandle, gpg: &GpgHandle) {
    Command::cargo_bin(env!("CARGO_PKG_NAME"))
        .unwrap()
        .write_stdin(stdin)
        .arg("--cargo-plugin")
        .env_remove("PASSWORD_STORE_SIGNING_KEY")
        .env_remove("PASSWORD_STORE_DIR")
        .env_remove("PASSWORD_STORE_GENERATED_LENGTH")
        .env_remove("GPG_TTY")
        .env("PASSWORD_STORE_DIR", pass.dir())
        .env("GNUPGHOME", &gpg.home_dir())
        .assert()
        .stdout(predicate::eq(want_stdout.as_bytes()))
        .stderr(predicate::str::is_empty());
}
