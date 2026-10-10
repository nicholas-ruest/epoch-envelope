use std::{path::Path, process::Command};

fn example(name: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join(name)
        .display()
        .to_string()
}

fn command(plan: &str, format: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_epoch-envelope"))
        .args([
            "--policy",
            &example("policy.toml"),
            "--plan",
            &example(plan),
            "--format",
            format,
        ])
        .output()
        .expect("CLI should run")
}

#[test]
fn valid_plan_exits_zero() {
    let output = command("valid-plan.json", "text");
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Allow simulated-surface-code-17"));
}

#[test]
fn invalid_plan_exits_two() {
    let output = command("invalid-plan.json", "text");
    assert_eq!(output.status.code(), Some(2));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Block stale-over-budget-plan"));
    assert!(stdout.contains("CALIBRATION_STALE"));
    assert!(stdout.contains("SHOT_BUDGET_EXCEEDED"));
}

#[test]
fn json_report_is_machine_readable() {
    let output = command("valid-plan.json", "json");
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["verdict"], "ALLOW");
    assert_eq!(value["metrics"]["critical_path_ms"], 752000);
}
