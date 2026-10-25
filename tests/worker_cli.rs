use std::process::Command;

#[test]
fn hidden_worker_rejects_invalid_input_before_starting_work() {
    for arguments in [
        vec!["__trace-worker"],
        vec![
            "__trace-worker",
            "/nonexistent/weld-root",
            "/nonexistent/weld-state",
            "0",
            "exit 0",
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_rpweld"))
            .args(arguments)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("rpweld: runner error:"));
    }
}
