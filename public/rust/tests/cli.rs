use std::process::Command;

#[test]
fn help_exits_successfully_and_lists_core_commands() {
    let output = Command::new(env!("CARGO_BIN_EXE_sc"))
        .arg("--help")
        .output()
        .expect("SC Archive binary should start");
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("pack"));
    assert!(text.contains("unpack"));
    assert!(text.contains("recover"));
    assert!(text.contains("inspect"));
    assert!(text.contains("verify"));
}

#[test]
fn version_is_reported() {
    let output = Command::new(env!("CARGO_BIN_EXE_sc"))
        .arg("--version")
        .output()
        .expect("SC Archive binary should start");
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("1.0.0"));
}
